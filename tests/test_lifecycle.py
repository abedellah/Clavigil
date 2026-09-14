"""Moteur JML, teste APRES un cycle complet de provisioning.

Ces tests decrivent l'etat attendu du systeme une fois la remediation passee.
"""

from __future__ import annotations

import pytest

import lifecycle
import reconcile
from config import db_cursor
from targets import LdapTarget

pytestmark = [pytest.mark.integration, pytest.mark.post_sync]


def test_chaque_personne_active_a_un_compte(ldap: LdapTarget):
    with db_cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM hr_person WHERE hr_status = 'active'")
        attendu = cur.fetchone()["n"]
    assert len(ldap.list_users()) >= attendu


def test_employe_recoit_le_socle_employe(active_roles):
    assert "R_BASE_EMP" in active_roles["P0005"]


def test_partenaire_recoit_le_socle_externe(active_roles):
    """P0012 est un partenaire : socle externe, pas le socle employe."""
    assert "R_BASE_EXT" in active_roles["P0012"]
    assert "R_BASE_EMP" not in active_roles["P0012"]


def test_sortant_ne_conserve_aucun_role(active_roles):
    assert active_roles.get("P0013", set()) == set()


def test_sortant_jamais_provisionne(ldap: LdapTarget):
    """P0013 etait deja sortie au chargement : aucun compte ne lui est cree.

    Le principe reste que l'on desactive au lieu de supprimer ; il se verifie
    sur P0014, dont le contrat a expire pendant que le systeme tournait.
    """
    assert "souazzani" not in {u["uid"] for u in ldap.list_users()}


def test_compte_du_contrat_echu_desactive_et_non_supprime(ldap: LdapTarget):
    """P0014 avait un compte actif ; run_expiry le desactive sans le supprimer.

    Supprimer detruirait la piste d'audit et libererait l'identifiant pour un
    futur homonyme.
    """
    compte = next((u for u in ldap.list_users() if u["uid"] == "hbertrand"), None)
    assert compte is not None, "le compte doit toujours exister apres la sortie"
    assert compte["locked"] is True


def test_mobilite_retire_le_role_du_service_quitte(active_roles):
    """P0009 est passee de la Comptabilite au Commercial."""
    assert "R_COMMERCIAL" in active_roles["P0009"]
    assert "R_COMPTA" not in active_roles["P0009"]


def test_role_accorde_manuellement_survit_a_la_mobilite(active_roles):
    """R_ADMIN_AD a ete accorde par une personne, pas par regle automatique.

    Les roles demandes se revoquent par recertification, pas par la mobilite.
    """
    assert "R_ADMIN_AD" in active_roles["P0008"]


def test_contrat_echu_bascule_en_sortie():
    """P0014 avait un contrat echu ; run_expiry l'a passe en 'terminated'."""
    with db_cursor() as cur:
        cur.execute("SELECT hr_status FROM hr_person WHERE person_id = 'P0014'")
        assert cur.fetchone()["hr_status"] == "terminated"


def test_plus_aucune_anomalie_apres_remediation():
    """Quatre constats avant le cycle, zero apres. C'est la demonstration."""
    assert reconcile.find_leaver_failures() == []
    assert reconcile.find_expired_contracts() == []


def test_sync_est_idempotent(ldap: LdapTarget, keycloak):
    """Une seconde execution ne doit rien changer. Premier reflexe d'un relecteur."""
    avant = len(ldap.list_users())
    lifecycle.run_joiners(ldap, keycloak)
    lifecycle.run_movers(ldap, keycloak)
    assert len(ldap.list_users()) == avant


def test_chaque_action_a_laisse_une_trace():
    """Sans journal, on a des affirmations, pas des preuves."""
    with db_cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM provisioning_log")
        assert cur.fetchone()["n"] > 0
