"""Connectors to the target systems.

This module is complete and working. It exists so you spend your time on
lifecycle and governance logic rather than on LDAP boilerplate — the part a
consultant is actually paid to reason about.

Read it anyway. In an interview you will be asked how provisioning reaches a
directory, and "I used a library" is not an answer. Know what a DN is, what
inetOrgPerson requires, and why group membership is stored on the group rather
than on the user in this schema.
"""

from __future__ import annotations

import time

import jwt
import requests
from ldap3 import ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, Connection, Server

from config import (
    KEYCLOAK_ADMIN,
    KEYCLOAK_ADMIN_PASSWORD,
    KEYCLOAK_REALM,
    KEYCLOAK_URL,
    LDAP_BIND_DN,
    LDAP_BIND_PASSWORD,
    LDAP_GROUPS_OU,
    LDAP_HOST,
    LDAP_PEOPLE_OU,
    LDAP_PORT,
)


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------
class LdapTarget:
    """Thin wrapper over the demo directory."""

    def __init__(self) -> None:
        server = Server(LDAP_HOST, port=LDAP_PORT, get_info=ALL)
        self.conn = Connection(
            server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True
        )

    def ensure_org_units(self) -> None:
        for ou_dn, ou_name in ((LDAP_PEOPLE_OU, "people"), (LDAP_GROUPS_OU, "groups")):
            if not self._exists(ou_dn):
                self.conn.add(ou_dn, "organizationalUnit", {"ou": ou_name})

    def user_dn(self, uid: str) -> str:
        return f"uid={uid},{LDAP_PEOPLE_OU}"

    def group_dn(self, name: str) -> str:
        return f"cn={name},{LDAP_GROUPS_OU}"

    def _exists(self, dn: str) -> bool:
        return self.conn.search(dn, "(objectClass=*)", search_scope="BASE")

    def create_user(
        self, uid: str, first_name: str, last_name: str, email: str, title: str
    ) -> bool:
        """Create an inetOrgPerson. Returns False if it already exists."""
        dn = self.user_dn(uid)
        if self._exists(dn):
            return False
        return self.conn.add(
            dn,
            ["inetOrgPerson", "organizationalPerson", "person", "top"],
            {
                "uid": uid,
                "cn": f"{first_name} {last_name}",
                "sn": last_name,
                "givenName": first_name,
                "mail": email,
                "title": title,
            },
        )

    def update_user(self, uid: str, **attributes: str) -> bool:
        changes = {k: [(MODIFY_REPLACE, [v])] for k, v in attributes.items()}
        return self.conn.modify(self.user_dn(uid), changes)

    def disable_user(self, uid: str) -> bool:
        """Disable rather than delete.

        Deleting an identity destroys the audit trail and frees the uid for
        reuse, which corrupts historical logs. Every serious IGA deployment
        disables and retains. Say this out loud in an interview.
        """
        return self.conn.modify(
            self.user_dn(uid),
            {"pwdAccountLockedTime": [(MODIFY_REPLACE, ["000001010000Z"])]},
        )

    def list_users(self) -> list[dict]:
        self.conn.search(
            LDAP_PEOPLE_OU,
            "(objectClass=inetOrgPerson)",
            attributes=["uid", "cn", "mail", "title", "pwdAccountLockedTime"],
        )
        return [
            {
                "uid": str(e.uid),
                "cn": str(e.cn),
                "mail": str(e.mail),
                "title": str(e.title),
                "locked": bool(e.pwdAccountLockedTime),
            }
            for e in self.conn.entries
        ]

    def ensure_group(self, name: str) -> None:
        dn = self.group_dn(name)
        if not self._exists(dn):
            self.conn.add(dn, "groupOfNames", {"cn": name, "member": [LDAP_BIND_DN]})

    def add_to_group(self, uid: str, group: str) -> bool:
        self.ensure_group(group)
        return self.conn.modify(
            self.group_dn(group), {"member": [(MODIFY_ADD, [self.user_dn(uid)])]}
        )

    def remove_from_group(self, uid: str, group: str) -> bool:
        return self.conn.modify(
            self.group_dn(group), {"member": [(MODIFY_DELETE, [self.user_dn(uid)])]}
        )

    def group_members(self, group: str) -> list[str]:
        if not self.conn.search(
            self.group_dn(group),
            "(objectClass=groupOfNames)",
            search_scope="BASE",
            attributes=["member"],
        ):
            return []
        return [str(m) for m in self.conn.entries[0].member]


# ---------------------------------------------------------------------------
# Keycloak
# ---------------------------------------------------------------------------
class KeycloakTarget:
    """Admin REST client for the demo realm."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self._expire_a = 0.0
        self._rafraichir_si_necessaire()

    def _demander_jeton(self) -> str:
        """Flot OAuth 2.0 "password" contre le realm master.

        C'est le flot le plus faible d'OAuth 2.0, retire d'OAuth 2.1. Il est
        acceptable ici parce que le client est un script d'administration qui
        detient legitimement les identifiants. Une application utilisateur
        devrait utiliser le flot "authorization code" avec PKCE.
        """
        response = self.session.post(
            f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": KEYCLOAK_ADMIN,
                "password": KEYCLOAK_ADMIN_PASSWORD,
            },
            timeout=10,
        )
        response.raise_for_status()
        return response.json()["access_token"]

    def _rafraichir_si_necessaire(self) -> None:
        """Redemande un jeton avant son expiration.

        Le jeton d'acces Keycloak dure quelques minutes. Le demander une seule
        fois au demarrage suffit pour une demo et casse des qu'un traitement
        dure. On lit la claim "exp" du JWT pour savoir quand le renouveler, avec
        30 secondes de marge.

        La signature n'est pas verifiee ici : nous sommes le destinataire du
        jeton, pas celui qui doit lui faire confiance. C'est l'API qui le
        recoit qui doit valider signature, issuer, audience et expiration
        (voir src/demo_api.py).
        """
        if time.time() < self._expire_a:
            return

        jeton = self._demander_jeton()
        claims = jwt.decode(jeton, options={"verify_signature": False})
        self._expire_a = float(claims["exp"]) - 30
        self.session.headers["Authorization"] = f"Bearer {jeton}"

    def _url(self, path: str) -> str:
        self._rafraichir_si_necessaire()
        return f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}{path}"

    def find_user(self, username: str) -> dict | None:
        response = self.session.get(
            self._url("/users"), params={"username": username, "exact": "true"}, timeout=10
        )
        response.raise_for_status()
        results = response.json()
        return results[0] if results else None

    def create_user(self, username: str, first_name: str, last_name: str, email: str) -> str | None:
        response = self.session.post(
            self._url("/users"),
            json={
                "username": username,
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "enabled": True,
                "emailVerified": False,
                "requiredActions": ["UPDATE_PASSWORD", "CONFIGURE_TOTP"],
            },
            timeout=10,
        )
        if response.status_code == 409:
            return None
        response.raise_for_status()
        return response.headers["Location"].rsplit("/", 1)[-1]

    def set_enabled(self, user_id: str, enabled: bool) -> None:
        response = self.session.put(
            self._url(f"/users/{user_id}"), json={"enabled": enabled}, timeout=10
        )
        response.raise_for_status()

    def list_users(self) -> list[dict]:
        response = self.session.get(self._url("/users"), params={"max": 1000}, timeout=10)
        response.raise_for_status()
        return response.json()

    def ensure_group(self, name: str) -> str:
        response = self.session.get(self._url("/groups"), params={"search": name}, timeout=10)
        response.raise_for_status()
        for group in response.json():
            if group["name"] == name:
                return group["id"]
        created = self.session.post(self._url("/groups"), json={"name": name}, timeout=10)
        created.raise_for_status()
        return created.headers["Location"].rsplit("/", 1)[-1]

    def add_to_group(self, user_id: str, group_name: str) -> None:
        group_id = self.ensure_group(group_name)
        response = self.session.put(self._url(f"/users/{user_id}/groups/{group_id}"), timeout=10)
        response.raise_for_status()

    def remove_from_group(self, user_id: str, group_name: str) -> None:
        group_id = self.ensure_group(group_name)
        response = self.session.delete(self._url(f"/users/{user_id}/groups/{group_id}"), timeout=10)
        response.raise_for_status()

    def user_groups(self, user_id: str) -> list[str]:
        response = self.session.get(self._url(f"/users/{user_id}/groups"), timeout=10)
        response.raise_for_status()
        return [g["name"] for g in response.json()]
