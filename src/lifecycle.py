"""Moteur de cycle de vie des identites : arrivee, mobilite, depart, expiration.

Ordre d'execution : run_joiners, run_movers, run_leavers, run_expiry.
On cree les comptes avant de calculer les droits, et on traite les departs
avant les expirations pour que les contrats echus repassent par le meme
chemin de sortie.
"""

from __future__ import annotations

import unicodedata

from config import db_cursor, log_action
from targets import KeycloakTarget, LdapTarget

# ---------------------------------------------------------------------------
# Petites fonctions utilitaires
# ---------------------------------------------------------------------------


def sans_accents(texte: str) -> str:
    """Retire les accents et met en minuscules. 'Benali' -> 'benali'."""
    decompose = unicodedata.normalize("NFKD", texte)
    return "".join(c for c in decompose if not unicodedata.combining(c)).lower()


def fabriquer_uid(prenom: str, nom: str, deja_pris: set[str]) -> str:
    """Identifiant de compte : premiere lettre du prenom + nom.

    En cas de collision (deux personnes nommees Alaoui), on ajoute un chiffre.
    Le probleme est reel : il finira par se produire dans toute entreprise.
    """
    base = sans_accents(prenom)[0] + sans_accents(nom)
    base = "".join(c for c in base if c.isalnum())
    uid = base
    compteur = 2
    while uid in deja_pris:
        uid = f"{base}{compteur}"
        compteur += 1
    return uid


def lire_personnes(statut: str | None = None) -> list[dict]:
    """Personnes du referentiel RH, filtrees par statut si demande."""
    with db_cursor() as cur:
        if statut is None:
            cur.execute("SELECT * FROM hr_person ORDER BY person_id")
        else:
            cur.execute(
                "SELECT * FROM hr_person WHERE hr_status = %s ORDER BY person_id",
                (statut,),
            )
        return cur.fetchall()


def uids_existants() -> set[str]:
    with db_cursor() as cur:
        cur.execute("SELECT account_uid FROM hr_person WHERE account_uid IS NOT NULL")
        return {row["account_uid"] for row in cur.fetchall()}


def tous_les_roles() -> set[str]:
    with db_cursor() as cur:
        cur.execute("SELECT role_id FROM business_role")
        return {row["role_id"] for row in cur.fetchall()}


def roles_actifs(person_id: str, seulement_birthright: bool = False) -> set[str]:
    """Roles detenus actuellement (non revoques) par une personne."""
    requete = "SELECT role_id FROM role_assignment WHERE person_id = %s AND revoked_at IS NULL"
    if seulement_birthright:
        requete += " AND granted_by = 'birthright'"
    with db_cursor() as cur:
        cur.execute(requete, (person_id,))
        return {row["role_id"] for row in cur.fetchall()}


def attribuer_role(person_id: str, role_id: str, accorde_par: str) -> None:
    with db_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO role_assignment (person_id, role_id, granted_by) VALUES (%s, %s, %s)",
            (person_id, role_id, accorde_par),
        )


def revoquer_role(person_id: str, role_id: str, motif: str) -> None:
    """On ne supprime jamais la ligne : on la date. L'historique doit rester lisible."""
    with db_cursor(commit=True) as cur:
        cur.execute(
            "UPDATE role_assignment SET revoked_at = now(), revocation_note = %s "
            "WHERE person_id = %s AND role_id = %s AND revoked_at IS NULL",
            (motif, person_id, role_id),
        )


def relire_uid(person_id: str) -> str | None:
    with db_cursor() as cur:
        cur.execute("SELECT account_uid FROM hr_person WHERE person_id = %s", (person_id,))
        ligne = cur.fetchone()
        return ligne["account_uid"] if ligne else None


# ---------------------------------------------------------------------------
# Regles d'attribution
# ---------------------------------------------------------------------------


def compute_birthright_roles(person: dict) -> set[str]:
    """Roles accordes automatiquement a partir des seuls attributs RH.

    Deux criteres, lus dans la table business_role :
      - auto_population : correspond a la population de la personne
      - auto_department : correspond a son service

    Prestataires et partenaires partagent le meme socle externe, donc on ramene
    les deux a la valeur 'external' utilisee dans le catalogue. Les regles
    restent en base : ajouter un service ne demande aucune modification de code.
    """
    if person["population"] == "employee":
        cle_population = "employee"
    else:
        cle_population = "external"

    roles: set[str] = set()
    with db_cursor() as cur:
        cur.execute("SELECT * FROM business_role WHERE is_birthright = true")
        for regle in cur.fetchall():
            if regle["auto_population"] == cle_population:
                roles.add(regle["role_id"])
            if regle["auto_department"] == person["department"]:
                roles.add(regle["role_id"])
    return roles


def desired_groups(person_id: str) -> set[str]:
    """Groupes cibles attendus : un groupe par role actif.

    On part de tous les roles actifs, pas seulement des roles de naissance :
    un role demande comme R_TRESORERIE doit lui aussi etre provisionne.
    """
    return roles_actifs(person_id)


def provisionner_groupes(
    person_id: str, uid: str | None, ldap: LdapTarget, keycloak: KeycloakTarget
) -> None:
    """Aligne l'appartenance aux groupes, dans LDAP et dans Keycloak."""
    if uid is None:
        return

    attendus = desired_groups(person_id)
    dn = ldap.user_dn(uid)

    # --- LDAP
    actuels_ldap = set()
    for groupe in tous_les_roles():
        if dn in ldap.group_members(groupe):
            actuels_ldap.add(groupe)

    for groupe in attendus - actuels_ldap:
        ldap.add_to_group(uid, groupe)
        log_action(person_id, "ldap", "add_group", "success", groupe)
    for groupe in actuels_ldap - attendus:
        ldap.remove_from_group(uid, groupe)
        log_action(person_id, "ldap", "remove_group", "success", groupe)

    # --- Keycloak
    compte = keycloak.find_user(uid)
    if compte is None:
        return
    actuels_kc = set(keycloak.user_groups(compte["id"]))
    for groupe in attendus - actuels_kc:
        keycloak.add_to_group(compte["id"], groupe)
        log_action(person_id, "keycloak", "add_group", "success", groupe)
    for groupe in actuels_kc - attendus:
        keycloak.remove_from_group(compte["id"], groupe)
        log_action(person_id, "keycloak", "remove_group", "success", groupe)


# ---------------------------------------------------------------------------
# Les quatre processus
# ---------------------------------------------------------------------------


def run_joiners(ldap: LdapTarget, keycloak: KeycloakTarget) -> int:
    """Cree les comptes des personnes presentes au RH mais absentes des cibles.

    Les droits ne sont pas calcules ici : run_movers s'en charge pour tout le
    monde, nouveaux compris. Une seule fonction decide des roles, ce qui evite
    d'avoir deux regles qui divergent avec le temps.
    """
    traites = 0
    pris = uids_existants()

    for personne in lire_personnes(statut="active"):
        if personne["account_uid"] is not None:
            continue  # deja provisionne

        uid = fabriquer_uid(personne["first_name"], personne["last_name"], pris)
        pris.add(uid)

        cree_ldap = ldap.create_user(
            uid,
            personne["first_name"],
            personne["last_name"],
            personne["email"],
            personne["job_title"],
        )
        log_action(
            personne["person_id"],
            "ldap",
            "create_user",
            "success" if cree_ldap else "skipped",
            uid,
        )

        # requiredActions force la definition d'un mot de passe et l'enrolement
        # MFA : le compte existe mais reste inutilisable tant que la personne
        # n'a pas fait les deux.
        cree_kc = keycloak.create_user(
            uid, personne["first_name"], personne["last_name"], personne["email"]
        )
        log_action(
            personne["person_id"],
            "keycloak",
            "create_user",
            "success" if cree_kc else "skipped",
            uid,
        )

        with db_cursor(commit=True) as cur:
            cur.execute(
                "UPDATE hr_person SET account_uid = %s WHERE person_id = %s",
                (uid, personne["person_id"]),
            )
        traites += 1

    return traites


def run_movers(ldap: LdapTarget, keycloak: KeycloakTarget) -> int:
    """Recalcule les roles de naissance de chaque personne active.

    C'est le plus important des quatre, et le seul qui retire des droits.
    Quelqu'un passe de la Comptabilite au Commercial : il gagne le role
    commercial et doit perdre le role comptable. L'accumulation de droits au fil
    des mutations est le constat d'audit le plus frequent en IAM.

    Les roles accordes manuellement (granted_by different de 'birthright') ne
    sont pas touches : ils se revoquent par recertification, pas ici. C'est une
    decision de conception, pas une regle universelle.
    """
    traites = 0

    for personne in lire_personnes(statut="active"):
        attendus = compute_birthright_roles(personne)
        detenus = roles_actifs(personne["person_id"], seulement_birthright=True)

        a_ajouter = attendus - detenus
        a_retirer = detenus - attendus

        for role in a_ajouter:
            attribuer_role(personne["person_id"], role, "birthright")
            log_action(personne["person_id"], "iam", "grant_role", "success", role)

        for role in a_retirer:
            revoquer_role(
                personne["person_id"],
                role,
                "Non justifie par les attributs RH courants",
            )
            log_action(personne["person_id"], "iam", "revoke_role", "success", role)

        if a_ajouter or a_retirer:
            traites += 1

        # On realigne les groupes meme sans changement de role : un appel a pu
        # echouer silencieusement lors d'une execution precedente.
        uid = personne["account_uid"] or relire_uid(personne["person_id"])
        provisionner_groupes(personne["person_id"], uid, ldap, keycloak)

    return traites


def run_leavers(ldap: LdapTarget, keycloak: KeycloakTarget) -> int:
    """Desactive les comptes des sortants et revoque tous leurs roles.

    On desactive, on ne supprime pas. Supprimer rendrait le journal d'audit
    illisible et libererait l'identifiant pour un futur homonyme. La purge
    intervient apres une periode de retention definie par la politique.
    """
    traites = 0

    for personne in lire_personnes(statut="terminated"):
        detenus = roles_actifs(personne["person_id"])
        uid = personne["account_uid"]

        if not detenus and uid is None:
            continue  # deja traite

        for role in detenus:
            revoquer_role(personne["person_id"], role, "Sortie des effectifs")
            log_action(personne["person_id"], "iam", "revoke_role", "success", role)

        if uid is not None:
            for role in detenus:
                ldap.remove_from_group(uid, role)
            ldap.disable_user(uid)
            log_action(personne["person_id"], "ldap", "disable_user", "success", uid)

            compte = keycloak.find_user(uid)
            if compte is not None:
                for groupe in keycloak.user_groups(compte["id"]):
                    keycloak.remove_from_group(compte["id"], groupe)
                keycloak.set_enabled(compte["id"], False)
                log_action(personne["person_id"], "keycloak", "disable_user", "success", uid)

        traites += 1

    return traites


def run_expiry(ldap: LdapTarget, keycloak: KeycloakTarget) -> int:
    """Passe en 'terminated' les externes dont le contrat est echu.

    Ce traitement tourne sur planification et non sur evenement RH : personne
    n'emet d'evenement le jour ou une date de fin est simplement depassee, il
    faut aller la chercher. C'est la difference entre une plateforme IGA et un
    simple script de provisioning.

    On change seulement le statut, puis on rappelle run_leavers : un seul chemin
    de sortie, donc un seul comportement a tester et a expliquer.
    """
    with db_cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE hr_person
            SET hr_status = 'terminated'
            WHERE hr_status = 'active'
              AND contract_end IS NOT NULL
              AND contract_end < current_date
            RETURNING person_id
            """
        )
        expires = [row["person_id"] for row in cur.fetchall()]

    for person_id in expires:
        log_action(person_id, "iam", "contract_expired", "success", "Statut passe a terminated")

    if expires:
        run_leavers(ldap, keycloak)

    return len(expires)
