"""Reconciliation des habilitations et restitution pour la gouvernance.

La reconciliation repond a une question a laquelle personne ne sait repondre de
memoire : ce qui est reellement provisionne dans les systemes cibles correspond
il a ce que dit le referentiel ? L'ecart entre les deux est l'endroit ou se
trouvent tous les constats d'audit.
"""

from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

from config import db_cursor
from lifecycle import desired_groups, tous_les_roles
from targets import KeycloakTarget, LdapTarget

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"


# ---------------------------------------------------------------------------
# 1. Comptes orphelins
# ---------------------------------------------------------------------------


def find_orphan_accounts(ldap: LdapTarget, keycloak: KeycloakTarget) -> list[dict]:
    """Comptes existant dans une cible sans enregistrement RH correspondant.

    Personne ne les possede, donc personne ne les revoit : ils traversent toutes
    les campagnes de recertification sans etre vus, puisqu'aucun manager ne les
    trouve dans sa liste. Un compte orphelin actif est nettement plus grave
    qu'un compte orphelin desactive, d'ou la colonne severite.

    Pour en fabriquer un et tester : `make ldap-orphan`.
    """
    with db_cursor() as cur:
        cur.execute("SELECT account_uid FROM hr_person WHERE account_uid IS NOT NULL")
        connus = {ligne["account_uid"] for ligne in cur.fetchall()}

    constats = []

    for compte in ldap.list_users():
        if compte["uid"] not in connus:
            constats.append(
                {
                    "system": "ldap",
                    "account": compte["uid"],
                    "enabled": not compte["locked"],
                    "severity": "high" if not compte["locked"] else "medium",
                    "detail": "Compte annuaire sans enregistrement RH",
                }
            )

    for compte in keycloak.list_users():
        if compte["username"] not in connus:
            constats.append(
                {
                    "system": "keycloak",
                    "account": compte["username"],
                    "enabled": compte.get("enabled", False),
                    "severity": "high" if compte.get("enabled") else "medium",
                    "detail": "Compte IdP sans enregistrement RH",
                }
            )

    return constats


# ---------------------------------------------------------------------------
# 2. Comptes dormants
# ---------------------------------------------------------------------------


def find_dormant_accounts(days: int = 90) -> list[dict]:
    """Comptes sans activite de provisioning depuis la fenetre donnee.

    LIMITE ASSUMEE : ce laboratoire ne collecte pas les journaux
    d'authentification. On approxime donc la dormance a partir du journal de
    provisioning, ce qui mesure l'activite de l'outil, pas celle de la personne.
    Pour un resultat exploitable il faudrait brancher les evenements Keycloak.
    Cette limite est ecrite dans le rapport : annoncer ce que la donnee ne
    permet pas est ce qui distingue une evaluation d'une opinion.
    """
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT p.person_id, p.account_uid, p.first_name, p.last_name,
                   max(l.occurred_at) AS derniere_activite
            FROM hr_person p
            LEFT JOIN provisioning_log l ON l.person_id = p.person_id
            WHERE p.hr_status = 'active' AND p.account_uid IS NOT NULL
            GROUP BY p.person_id, p.account_uid, p.first_name, p.last_name
            HAVING max(l.occurred_at) IS NULL
                OR max(l.occurred_at) < now() - make_interval(days => %s)
            ORDER BY p.person_id
            """,
            (days,),
        )
        return [
            {
                "person_id": ligne["person_id"],
                "account": ligne["account_uid"],
                "name": f"{ligne['first_name']} {ligne['last_name']}",
                "last_activity": ligne["derniere_activite"],
                "severity": "medium",
                "detail": f"Aucune activite depuis plus de {days} jours",
            }
            for ligne in cur.fetchall()
        ]


# ---------------------------------------------------------------------------
# 3. Ecarts d'habilitations
# ---------------------------------------------------------------------------


def find_entitlement_drift(ldap: LdapTarget, keycloak: KeycloakTarget) -> list[dict]:
    """Differences entre roles accordes et appartenance reelle aux groupes.

    Les deux sens sont reportes separement, parce que le risque n'est pas le
    meme : "accorde mais non provisionne" est un incident de service desk,
    "provisionne mais non accorde" est un acces non autorise.
    """
    constats = []
    roles = tous_les_roles()

    # On lit une seule fois l'appartenance de chaque groupe LDAP.
    membres_ldap: dict[str, set[str]] = {}
    for role in roles:
        membres_ldap[role] = set(ldap.group_members(role))

    with db_cursor() as cur:
        cur.execute(
            "SELECT person_id, account_uid FROM hr_person "
            "WHERE hr_status = 'active' AND account_uid IS NOT NULL"
        )
        personnes = cur.fetchall()

    for personne in personnes:
        uid = personne["account_uid"]
        dn = ldap.user_dn(uid)
        attendus = desired_groups(personne["person_id"])

        reels_ldap = {role for role in roles if dn in membres_ldap[role]}

        compte = keycloak.find_user(uid)
        reels_kc = set(keycloak.user_groups(compte["id"])) if compte else set()

        for cible, reels in (("ldap", reels_ldap), ("keycloak", reels_kc)):
            for role in attendus - reels:
                constats.append(
                    {
                        "person_id": personne["person_id"],
                        "account": uid,
                        "system": cible,
                        "role_id": role,
                        "direction": "accorde_non_provisionne",
                        "severity": "low",
                        "detail": "La personne ne peut pas exercer son role",
                    }
                )
            for role in reels - attendus:
                constats.append(
                    {
                        "person_id": personne["person_id"],
                        "account": uid,
                        "system": cible,
                        "role_id": role,
                        "direction": "provisionne_non_accorde",
                        "severity": "high",
                        "detail": "Acces non autorise",
                    }
                )

    return constats


# ---------------------------------------------------------------------------
# 4. Violations de separation des taches
# ---------------------------------------------------------------------------


def find_sod_violations() -> list[dict]:
    """Personnes detenant les deux moities d'une regle de separation des taches.

    La jointure porte sur les deux roles a la fois : une personne ne detenant
    qu'une moitie ne doit pas remonter. La justification metier est renvoyee
    avec le constat, sans quoi le manager qui doit decider n'a aucune base.
    """
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT r.rule_id, r.severity, r.rationale,
                   r.role_a, r.role_b,
                   p.person_id, p.first_name, p.last_name, p.department
            FROM sod_rule r
            JOIN role_assignment a ON a.role_id = r.role_a AND a.revoked_at IS NULL
            JOIN role_assignment b ON b.role_id = r.role_b AND b.revoked_at IS NULL
                                  AND b.person_id = a.person_id
            JOIN hr_person p ON p.person_id = a.person_id
            ORDER BY p.person_id, r.rule_id
            """
        )
        return [
            {
                "person_id": ligne["person_id"],
                "name": f"{ligne['first_name']} {ligne['last_name']}",
                "department": ligne["department"],
                "rule_id": ligne["rule_id"],
                "roles": f"{ligne['role_a']} + {ligne['role_b']}",
                "severity": ligne["severity"],
                "rationale": ligne["rationale"],
            }
            for ligne in cur.fetchall()
        ]


# ---------------------------------------------------------------------------
# 5. Contrats expires
# ---------------------------------------------------------------------------


def find_expired_contracts(as_of: date | None = None) -> list[dict]:
    """Externes dont la date de fin est depassee mais toujours actifs.

    Requete courte, et la classe de constat la plus grave en mission : un acces
    qui a survecu a son autorisation.
    """
    reference = as_of or date.today()
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT person_id, first_name, last_name, population,
                   department, contract_end
            FROM hr_person
            WHERE hr_status = 'active'
              AND contract_end IS NOT NULL
              AND contract_end < %s
            ORDER BY contract_end
            """,
            (reference,),
        )
        return [
            {
                "person_id": ligne["person_id"],
                "name": f"{ligne['first_name']} {ligne['last_name']}",
                "population": ligne["population"],
                "department": ligne["department"],
                "contract_end": ligne["contract_end"],
                "severity": "high",
                "detail": "Contrat echu, compte toujours actif",
            }
            for ligne in cur.fetchall()
        ]


# ---------------------------------------------------------------------------
# 6. Sorties non traitees
# ---------------------------------------------------------------------------


def find_leaver_failures() -> list[dict]:
    """Personnes sorties du RH conservant des roles actifs.

    Se rapporte au controle de deprovisionnement. C'est en general le constat
    qui retient l'attention de la direction, parce que le risque est intuitif
    pour un lecteur non technique.
    """
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT p.person_id, p.first_name, p.last_name, p.department,
                   count(a.assignment_id) AS nb_roles,
                   string_agg(a.role_id, ', ' ORDER BY a.role_id) AS roles
            FROM hr_person p
            JOIN role_assignment a ON a.person_id = p.person_id
                                  AND a.revoked_at IS NULL
            WHERE p.hr_status = 'terminated'
            GROUP BY p.person_id, p.first_name, p.last_name, p.department
            ORDER BY p.person_id
            """
        )
        return [
            {
                "person_id": ligne["person_id"],
                "name": f"{ligne['first_name']} {ligne['last_name']}",
                "department": ligne["department"],
                "role_count": ligne["nb_roles"],
                "roles": ligne["roles"],
                "severity": "high",
                "detail": "Sortie non traitee : droits toujours actifs",
            }
            for ligne in cur.fetchall()
        ]


# ---------------------------------------------------------------------------
# 7. Campagne de recertification
# ---------------------------------------------------------------------------


def export_certification_campaign(campaign_id: str) -> Path:
    """Genere un fichier CSV par manager pour une campagne de revue des acces.

    Les campagnes reelles sont lues par des managers, pas par la securite : les
    colonnes sont donc en clair, avec la description du role plutot que son
    code. Les colonnes decision et justification restent vides, c'est le manager
    qui les remplit.
    """
    with db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO certification_campaign (campaign_id, display_name, scope_note)
            VALUES (%s, %s, %s)
            ON CONFLICT (campaign_id) DO NOTHING
            """,
            (
                campaign_id,
                f"Revue des acces {campaign_id}",
                "Tous les roles actifs des personnes actives, revus par le manager.",
            ),
        )
        # Le reviseur est le manager, ou le sponsor pour un partenaire, ou la
        # direction a defaut.
        cur.execute(
            """
            INSERT INTO certification_item (campaign_id, person_id, role_id, reviewer_id)
            SELECT %s, p.person_id, a.role_id,
                   coalesce(p.manager_id, p.sponsor_id, 'P0001')
            FROM hr_person p
            JOIN role_assignment a ON a.person_id = p.person_id
                                  AND a.revoked_at IS NULL
            WHERE p.hr_status = 'active'
              AND NOT EXISTS (
                  SELECT 1 FROM certification_item i
                  WHERE i.campaign_id = %s AND i.person_id = p.person_id
                    AND i.role_id = a.role_id
              )
            """,
            (campaign_id, campaign_id),
        )

    with db_cursor() as cur:
        cur.execute(
            """
            SELECT rev.email AS reviewer_email,
                   sub.first_name || ' ' || sub.last_name AS collaborateur,
                   sub.department,
                   br.display_name AS role,
                   br.description AS ce_que_permet_le_role,
                   coalesce(max(e.risk_level), 'low') AS niveau_de_risque,
                   min(a.granted_at)::date AS accorde_le,
                   min(a.granted_by) AS accorde_par
            FROM certification_item i
            JOIN hr_person sub ON sub.person_id = i.person_id
            JOIN hr_person rev ON rev.person_id = i.reviewer_id
            JOIN business_role br ON br.role_id = i.role_id
            JOIN role_assignment a ON a.person_id = i.person_id
                                  AND a.role_id = i.role_id
                                  AND a.revoked_at IS NULL
            LEFT JOIN role_entitlement re ON re.role_id = i.role_id
            LEFT JOIN entitlement e ON e.entitlement_id = re.entitlement_id
            WHERE i.campaign_id = %s
            GROUP BY rev.email, collaborateur, sub.department, br.display_name,
                     br.description
            ORDER BY rev.email, collaborateur
            """,
            (campaign_id,),
        )
        lignes = cur.fetchall()

    dossier = REPORT_DIR / campaign_id
    dossier.mkdir(parents=True, exist_ok=True)

    par_manager: dict[str, list[dict]] = {}
    for ligne in lignes:
        par_manager.setdefault(ligne["reviewer_email"], []).append(ligne)

    colonnes = [
        "collaborateur",
        "department",
        "role",
        "ce_que_permet_le_role",
        "niveau_de_risque",
        "accorde_le",
        "accorde_par",
        "decision",
        "justification",
    ]

    for email, contenu in par_manager.items():
        chemin = dossier / f"{email.split('@')[0]}.csv"
        with chemin.open("w", newline="", encoding="utf-8") as fichier:
            writer = csv.DictWriter(fichier, fieldnames=colonnes, delimiter=";")
            writer.writeheader()
            for ligne in contenu:
                writer.writerow(
                    {
                        "collaborateur": ligne["collaborateur"],
                        "department": ligne["department"],
                        "role": ligne["role"],
                        "ce_que_permet_le_role": ligne["ce_que_permet_le_role"],
                        "niveau_de_risque": ligne["niveau_de_risque"],
                        "accorde_le": ligne["accorde_le"],
                        "accorde_par": ligne["accorde_par"],
                        "decision": "",
                        "justification": "",
                    }
                )

    return dossier


# ---------------------------------------------------------------------------
# 8. Rapport de synthese
# ---------------------------------------------------------------------------


def build_full_report() -> Path:
    """Execute tous les controles et ecrit un rapport Markdown.

    On ouvre sur ce qui ne va pas, pas sur la methodologie. Un lecteur qui ne
    lira qu'un paragraphe doit tomber sur les constats.
    """
    ldap = LdapTarget()
    keycloak = KeycloakTarget()

    controles = [
        ("Sorties non traitees", find_leaver_failures()),
        ("Contrats expires", find_expired_contracts()),
        ("Violations SoD", find_sod_violations()),
        ("Ecarts d'habilitations", find_entitlement_drift(ldap, keycloak)),
        ("Comptes orphelins", find_orphan_accounts(ldap, keycloak)),
        ("Comptes dormants", find_dormant_accounts()),
    ]

    ordre = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def severite_max(constats: list[dict]) -> str:
        if not constats:
            return "-"
        return min((c.get("severity", "low") for c in constats), key=lambda s: ordre[s])

    total = sum(len(constats) for _, constats in controles)

    lignes = [
        "# Rapport de reconciliation des habilitations",
        "",
        f"**{total} constatation(s)** sur {len(controles)} controles.",
        "",
        "| Controle | Constats | Severite max |",
        "|---|---|---|",
    ]
    for nom, constats in controles:
        lignes.append(f"| {nom} | {len(constats)} | {severite_max(constats)} |")

    for nom, constats in controles:
        lignes += ["", f"## {nom}", ""]
        if not constats:
            lignes.append("Aucune constatation.")
            continue
        colonnes = list(constats[0].keys())
        lignes.append("| " + " | ".join(colonnes) + " |")
        lignes.append("|" + "---|" * len(colonnes))
        for constat in constats:
            lignes.append("| " + " | ".join(str(constat.get(c, "")) for c in colonnes) + " |")

    lignes += [
        "",
        "## Remediation",
        "",
        "1. Executer `make sync` : traite les sorties, les contrats echus et la",
        "   mobilite. Cela resorbe la majorite des constats ci-dessus.",
        "2. Les violations SoD ne se corrigent pas automatiquement : elles",
        "   demandent un arbitrage du responsable metier, qui choisit quel role",
        "   retirer.",
        "3. Les comptes orphelins demandent une enquete : identifier le",
        "   proprietaire, puis rattacher ou desactiver.",
        "",
        "## Limites",
        "",
        "- La dormance est approximee a partir du journal de provisioning, faute",
        "  de collecte des evenements d'authentification.",
        "- Le perimetre est limite aux deux systemes cibles du laboratoire.",
    ]

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    chemin = REPORT_DIR / "reconciliation.md"
    chemin.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    return chemin
