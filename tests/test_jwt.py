"""Validation des jetons OIDC.

Ces tests sont de vrais tests unitaires : ils fabriquent une paire de cles et
signent leurs propres jetons, donc aucun conteneur n'est necessaire. Ils
tournent en millisecondes.

Ce sont les cas negatifs qui comptent. Accepter un jeton valide est facile ;
refuser un jeton emis pour une autre application est la verification que les
projets oublient, et c'est une faille reelle.
"""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

CLE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIQUE = CLE.public_key()

ISSUER = "http://localhost:8080/realms/demo"
AUDIENCE = "demo-api"


def fabriquer_jeton(**remplacements) -> str:
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "abc-123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "preferred_username": "lfassi",
        "groups": ["/R_BASE_EMP", "/R_COMPTA"],
    }
    claims.update(remplacements)
    return jwt.encode(claims, CLE, algorithm="RS256")


def decoder(jeton: str) -> dict:
    return jwt.decode(
        jeton,
        PUBLIQUE,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )


def test_jeton_valide_accepte():
    claims = decoder(fabriquer_jeton())
    assert claims["preferred_username"] == "lfassi"


def test_jeton_expire_refuse():
    jeton = fabriquer_jeton(exp=int(time.time()) - 10)
    with pytest.raises(jwt.ExpiredSignatureError):
        decoder(jeton)


def test_mauvaise_audience_refusee():
    """Un jeton emis pour une autre application du realm ne doit pas passer.

    C'est la verification la plus souvent desactivee, et la faille qui en
    resulte est reelle.
    """
    jeton = fabriquer_jeton(aud="une-autre-application")
    with pytest.raises(jwt.InvalidAudienceError):
        decoder(jeton)


def test_mauvais_issuer_refuse():
    jeton = fabriquer_jeton(iss="http://serveur-pirate/realms/demo")
    with pytest.raises(jwt.InvalidIssuerError):
        decoder(jeton)


def test_signature_falsifiee_refusee():
    """Un jeton signe par une autre cle doit etre rejete."""
    autre = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jeton = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "x",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
        autre,
        algorithm="RS256",
    )
    with pytest.raises(jwt.InvalidSignatureError):
        decoder(jeton)


def test_algorithme_none_refuse():
    """L'attaque "alg: none" : un jeton non signe ne doit jamais etre accepte."""
    jeton = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "exp": int(time.time()) + 300},
        key="",
        algorithm="none",
    )
    with pytest.raises(jwt.InvalidTokenError):
        decoder(jeton)


def test_claim_obligatoire_manquante_refusee():
    jeton = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 300},
        CLE,
        algorithm="RS256",
    )
    with pytest.raises(jwt.MissingRequiredClaimError):
        decoder(jeton)
