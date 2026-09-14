"""Configuration and database access. This module is complete — no work needed."""

import os
from contextlib import contextmanager

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

load_dotenv()

DB_DSN = (
    f"host={os.getenv('DB_HOST', 'localhost')} "
    f"port={os.getenv('DB_PORT', '5432')} "
    f"dbname={os.getenv('DB_NAME', 'iam')} "
    f"user={os.getenv('DB_USER', 'iam')} "
    f"password={os.getenv('DB_PASSWORD', '')}"
)

LDAP_HOST = os.getenv("LDAP_HOST", "localhost")
LDAP_PORT = int(os.getenv("LDAP_PORT", "389"))
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=demo,dc=local")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "cn=admin,dc=demo,dc=local")
LDAP_BIND_PASSWORD = os.getenv("LDAP_ADMIN_PASSWORD", "")
LDAP_PEOPLE_OU = f"ou=people,{LDAP_BASE_DN}"
LDAP_GROUPS_OU = f"ou=groups,{LDAP_BASE_DN}"

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "demo")
KEYCLOAK_ADMIN = os.getenv("KEYCLOAK_ADMIN", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "")


@contextmanager
def db_cursor(commit: bool = False):
    """Yield a dict-returning cursor, committing on clean exit if asked."""
    with psycopg.connect(DB_DSN, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            yield cur
        if commit:
            conn.commit()


def log_action(
    person_id: str | None,
    target_system: str,
    action: str,
    outcome: str,
    detail: str | None = None,
    error_message: str | None = None,
) -> None:
    """Append one row to the provisioning audit trail.

    Every write your engine performs against a target system must produce a log
    row, including failures and skips. In an audit that trail is the evidence
    that the process ran; without it you have assertions, not proof.
    """
    with db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO provisioning_log
                (person_id, target_system, action, outcome, detail, error_message)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (person_id, target_system, action, outcome, detail, error_message),
        )
