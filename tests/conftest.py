"""Shared fixtures.

Note something as you read this: almost every test below needs the running
stack, because the lifecycle rules read the database directly. That is a design
smell, and spotting it is worth more than the tests themselves.

If you refactor compute_birthright_roles to take the role definitions as an
argument instead of querying inside, it becomes a pure function you can test in
milliseconds with no containers. Doing that refactor, and being able to explain
why, is a strong answer to "how do you make code testable?".
"""

from __future__ import annotations

import pytest

from config import db_cursor
from targets import KeycloakTarget, LdapTarget


@pytest.fixture(scope="session")
def ldap() -> LdapTarget:
    return LdapTarget()


@pytest.fixture(scope="session")
def keycloak() -> KeycloakTarget:
    return KeycloakTarget()


@pytest.fixture
def active_roles():
    """Return {person_id: {role_id, ...}} for all non-revoked assignments."""
    with db_cursor() as cur:
        cur.execute("SELECT person_id, role_id FROM role_assignment WHERE revoked_at IS NULL")
        result: dict[str, set[str]] = {}
        for row in cur.fetchall():
            result.setdefault(row["person_id"], set()).add(row["role_id"])
        return result
