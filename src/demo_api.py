"""API de demonstration protegee par jeton OIDC.

Cette application represente une application cible du systeme d'information.
Elle ne connait aucun mot de passe : elle fait confiance a Keycloak, verifie le
jeton presente, et prend sa decision d'autorisation a partir des groupes qu'il
contient.

Les quatre verifications faites ici sont exactement celles qu'on oublie en
pratique :

  1. signature   - le jeton a bien ete emis par Keycloak (cle publique JWKS)
  2. issuer      - il vient du bon realm, pas d'un autre serveur
  3. audience    - il a ete emis POUR cette application, pas pour une autre
  4. expiration  - il n'est pas perime

La verification d'audience est la plus souvent desactivee, et c'est une faille
reelle : sans elle, un jeton emis pour n'importe quel client du realm ouvre
l'acces a cette API.
"""

from __future__ import annotations

import jwt
from flask import Flask, jsonify, request
from jwt import PyJWKClient

from config import KEYCLOAK_REALM, KEYCLOAK_URL

AUDIENCE = "demo-api"
ISSUER = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"

app = Flask(__name__)

# PyJWKClient telecharge et met en cache les cles publiques du realm, et suit le
# "kid" present dans l'en-tete du jeton. C'est ce qui permet a Keycloak de
# renouveler ses cles sans casser l'application.
jwks_client = PyJWKClient(JWKS_URL)


class JetonInvalide(Exception):
    pass


def valider_jeton(entete_authorization: str | None) -> dict:
    """Verifie le jeton et retourne ses claims. Leve JetonInvalide sinon."""
    if not entete_authorization or not entete_authorization.startswith("Bearer "):
        raise JetonInvalide("En-tete Authorization absent ou mal forme")

    jeton = entete_authorization.removeprefix("Bearer ")

    try:
        cle = jwks_client.get_signing_key_from_jwt(jeton)
    except Exception as erreur:
        raise JetonInvalide(f"Cle de signature introuvable : {erreur}") from erreur

    try:
        claims = jwt.decode(
            jeton,
            cle.key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["exp", "iat", "iss", "aud", "sub"],
            },
        )
    except jwt.ExpiredSignatureError as erreur:
        raise JetonInvalide("Jeton expire") from erreur
    except jwt.InvalidAudienceError as erreur:
        raise JetonInvalide("Jeton emis pour une autre application") from erreur
    except jwt.InvalidIssuerError as erreur:
        raise JetonInvalide("Jeton emis par un autre serveur") from erreur
    except jwt.InvalidTokenError as erreur:
        raise JetonInvalide(f"Jeton invalide : {erreur}") from erreur

    return claims


def groupes_du_jeton(claims: dict) -> set[str]:
    """Groupes portes par le jeton.

    Keycloak prefixe les groupes d'un '/'. On le retire pour retrouver le
    role_id du referentiel : '/R_COMPTA' devient 'R_COMPTA'.
    """
    return {g.lstrip("/") for g in claims.get("groups", [])}


def exiger_role(role_id: str):
    """Petit decorateur d'autorisation.

    L'authentification dit qui vous etes. L'autorisation dit ce que vous avez le
    droit de faire. Ce sont deux etapes distinctes et cette API les separe.
    """

    def decorateur(fonction):
        def wrapper(*args, **kwargs):
            try:
                claims = valider_jeton(request.headers.get("Authorization"))
            except JetonInvalide as erreur:
                return jsonify({"erreur": str(erreur)}), 401

            if role_id not in groupes_du_jeton(claims):
                return jsonify(
                    {
                        "erreur": "Acces refuse",
                        "role_requis": role_id,
                        "utilisateur": claims.get("preferred_username"),
                    }
                ), 403

            return fonction(claims, *args, **kwargs)

        wrapper.__name__ = fonction.__name__
        return wrapper

    return decorateur


@app.get("/api/public")
def public():
    """Aucun jeton requis. Sert de temoin quand on teste."""
    return jsonify({"message": "Ressource publique"})


@app.get("/api/profil")
def profil():
    """Authentifie mais sans role particulier : renvoie l'identite du porteur."""
    try:
        claims = valider_jeton(request.headers.get("Authorization"))
    except JetonInvalide as erreur:
        return jsonify({"erreur": str(erreur)}), 401

    return jsonify(
        {
            "sub": claims["sub"],
            "utilisateur": claims.get("preferred_username"),
            "email": claims.get("email"),
            "groupes": sorted(groupes_du_jeton(claims)),
            "expire_a": claims["exp"],
        }
    )


@app.get("/api/comptabilite")
@exiger_role("R_COMPTA")
def comptabilite(claims: dict):
    return jsonify(
        {
            "message": "Ecritures comptables",
            "consulte_par": claims.get("preferred_username"),
        }
    )


@app.get("/api/tresorerie")
@exiger_role("R_TRESORERIE")
def tresorerie(claims: dict):
    return jsonify(
        {
            "message": "Paiements en attente de validation",
            "consulte_par": claims.get("preferred_username"),
        }
    )


if __name__ == "__main__":
    # Serveur de developpement : laboratoire uniquement.
    app.run(host="127.0.0.1", port=5000)
