"""Command-line entrypoint. Working — it wires your functions together.

python src/main.py init          set up LDAP org units and groups
python src/main.py sync          run the full JML cycle
python src/main.py reconcile     run all reconciliation checks
python src/main.py report        write the Markdown reconciliation report
python src/main.py certify ID    export an access review campaign
python src/main.py status        show what is currently provisioned
"""

from __future__ import annotations

import sys

import lifecycle
import reconcile
from config import db_cursor
from targets import KeycloakTarget, LdapTarget

CHECKS = (
    ("Comptes orphelins", reconcile.find_orphan_accounts, True),
    ("Comptes dormants", reconcile.find_dormant_accounts, False),
    ("Ecarts d'habilitations", reconcile.find_entitlement_drift, True),
    ("Violations SoD", reconcile.find_sod_violations, False),
    ("Contrats expires", reconcile.find_expired_contracts, False),
    ("Sorties non traitees", reconcile.find_leaver_failures, False),
)


def cmd_init() -> None:
    ldap = LdapTarget()
    ldap.ensure_org_units()
    with db_cursor() as cur:
        cur.execute("SELECT role_id FROM business_role ORDER BY role_id")
        roles = [row["role_id"] for row in cur.fetchall()]
    keycloak = KeycloakTarget()
    for role in roles:
        ldap.ensure_group(role)
        keycloak.ensure_group(role)
    print(f"Initialised {len(roles)} groups in LDAP and Keycloak.")


def cmd_sync() -> None:
    ldap, keycloak = LdapTarget(), KeycloakTarget()
    for label, fn in (
        ("Joiners", lifecycle.run_joiners),
        ("Movers", lifecycle.run_movers),
        ("Leavers", lifecycle.run_leavers),
        ("Expiry", lifecycle.run_expiry),
    ):
        count = fn(ldap, keycloak)
        print(f"  {label:<10} {count} traite(s)")


def cmd_reconcile() -> None:
    ldap, keycloak = LdapTarget(), KeycloakTarget()
    total = 0
    for label, fn, needs_targets in CHECKS:
        rows = fn(ldap, keycloak) if needs_targets else fn()
        total += len(rows)
        print(f"  {label:<24} {len(rows)} constatation(s)")
        for row in rows:
            print(f"      {row}")
    print(f"\n{total} constatation(s) au total.")


def cmd_report() -> None:
    print(f"Report written to {reconcile.build_full_report()}")


def cmd_certify(campaign_id: str) -> None:
    print(f"Campaign exported to {reconcile.export_certification_campaign(campaign_id)}")


def cmd_status() -> None:
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT p.population,
                   count(*) FILTER (WHERE p.hr_status = 'active')     AS actifs,
                   count(*) FILTER (WHERE p.hr_status = 'terminated') AS sortis
            FROM hr_person p GROUP BY p.population ORDER BY p.population
            """
        )
        print("HR:")
        for row in cur.fetchall():
            print(f"  {row['population']:<12} {row['actifs']} actif(s), {row['sortis']} sorti(s)")
    ldap_users = LdapTarget().list_users()
    keycloak_users = KeycloakTarget().list_users()
    print(f"LDAP:     {len(ldap_users)} compte(s)")
    print(f"Keycloak: {len(keycloak_users)} compte(s)")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    command, args = sys.argv[1], sys.argv[2:]
    handlers = {
        "init": cmd_init,
        "sync": cmd_sync,
        "reconcile": cmd_reconcile,
        "report": cmd_report,
        "certify": cmd_certify,
        "status": cmd_status,
    }
    handler = handlers.get(command)
    if handler is None:
        print(__doc__)
        return 1
    handler(*args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
