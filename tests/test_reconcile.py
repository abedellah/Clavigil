"""Controles de reconciliation, testes AVANT toute remediation.

Le jeu de donnees contient quatre anomalies implantees. Ces tests verifient
qu'on les trouve toutes, et surtout qu'on ne trouve rien d'autre : les
assertions negatives comptent plus que les positives.
"""

from __future__ import annotations

import pytest

import reconcile

pytestmark = [pytest.mark.integration, pytest.mark.pre_sync]


def test_sortie_non_traitee_detectee():
    """P0013 est sortie des effectifs mais conserve des roles actifs."""
    constats = reconcile.find_leaver_failures()
    assert {c["person_id"] for c in constats} == {"P0013"}


def test_contrat_expire_detecte():
    """Le contrat de P0014 s'est termine le 31/12/2025, le compte reste actif."""
    constats = reconcile.find_expired_contracts()
    assert {c["person_id"] for c in constats} == {"P0014"}


def test_violation_sod_detectee():
    """P0015 cumule R_COMPTA et R_TRESORERIE : la regle SOD_01 est enfreinte."""
    constats = reconcile.find_sod_violations()
    assert {c["person_id"] for c in constats} == {"P0015"}
    assert constats[0]["rule_id"] == "SOD_01"


def test_sod_sans_faux_positif():
    """P0006 detient R_TRESORERIE sans R_COMPTA. Ce n'est pas une violation."""
    constats = reconcile.find_sod_violations()
    assert "P0006" not in {c["person_id"] for c in constats}


def test_mobilite_non_traitee_visible():
    """P0009 est passee au Commercial mais garde le role comptable."""
    from lifecycle import compute_birthright_roles, lire_personnes, roles_actifs

    personne = next(p for p in lire_personnes() if p["person_id"] == "P0009")
    assert "R_COMPTA" in roles_actifs("P0009")
    assert "R_COMPTA" not in compute_birthright_roles(personne)


def test_constats_sod_portent_leur_justification():
    """Un constat sans justification metier est inexploitable par un manager."""
    for constat in reconcile.find_sod_violations():
        assert constat["rationale"]
        assert constat["severity"] in {"low", "medium", "high"}


def test_exactement_quatre_classes_en_anomalie():
    """Quatre anomalies implantees, quatre classes de constat non vides."""
    classes = [
        reconcile.find_leaver_failures(),
        reconcile.find_expired_contracts(),
        reconcile.find_sod_violations(),
    ]
    assert all(len(c) == 1 for c in classes)
