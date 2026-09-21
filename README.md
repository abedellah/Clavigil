<p align="center">
  <img src="assets/banner.svg?v=2" alt="Clavigil, gouvernance du cycle de vie des identités" width="100%">
</p>

# Clavigil — gouvernance des identités et des accès

> Gouvernance du cycle de vie des identités, de l'arrivée au départ.

Laboratoire IAM auto-hébergé : provisioning automatisé du cycle de vie des
identités (arrivée / mobilité / départ) depuis un référentiel RH vers un
annuaire LDAP et un fournisseur d'identité, avec réconciliation des
habilitations, contrôle de séparation des tâches et campagne de
recertification des accès.

**Stack :** OpenLDAP · Keycloak · PostgreSQL · Python · OIDC / JWT

---

## Pourquoi ce projet

Ce laboratoire couvre, point par point, ce qui est attendu sur un poste IAM /
GRC / IT audit : cycle de vie des identités pour employés, prestataires et
partenaires ; analyse des comptes et des habilitations applicatives ;
authentification fédérée (OIDC) ; modèle de rôles et séparation des tâches ;
campagnes de recertification et documentation de contrôle.

---

## Architecture

| Composant | Rôle |
|---|---|
| PostgreSQL | Référentiel RH, catalogue d'habilitations, modèle de rôles, règles SoD, journal de provisioning, campagnes de certification |
| OpenLDAP | Annuaire cible, organisé en groupes par rôle métier |
| Keycloak | Fournisseur d'identité (OIDC), fédération et gestion des sessions |
| Moteur Python (`src/`) | Cycle de vie JML, connecteurs LDAP/Keycloak, contrôles de réconciliation, CLI |

## Démarrage

```bash
cp .env.example .env          # changez chaque mot de passe
docker compose up -d
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/main.py init       # crée les groupes dans LDAP et Keycloak
python src/main.py sync       # exécute le cycle JML complet
python src/main.py reconcile  # exécute les six contrôles
python src/main.py report     # génère le rapport Markdown
```

| Service | URL | Notes |
|---|---|---|
| Keycloak | http://localhost:8080 | console d'administration |
| OpenLDAP | localhost:389 | annuaire, interrogé via `ldapsearch` |
| PostgreSQL | localhost:5432 | base `iam` |

Pour inspecter l'annuaire : `make ldap-users` et `make ldap-groups`, qui
appellent `ldapsearch` dans le conteneur.

---

## Fonctionnalités

**Cycle de vie JML** (`src/lifecycle.py`) — arrivées, mobilité, départs et
expiration de contrat, appliqués automatiquement depuis le référentiel RH
vers LDAP et Keycloak.

**Réconciliation** (`src/reconcile.py`) — six contrôles indépendants :
comptes orphelins, comptes dormants, écarts d'habilitations (accordé vs
provisionné, dans les deux sens), violations de séparation des tâches,
contrats expirés, sorties non traitées. Chaque constat porte sa sévérité et
sa justification métier.

**Campagnes de recertification** — export d'une revue d'accès en un fichier
CSV par manager, avec les décisions et justifications à compléter.

**Rapport de synthèse** — un rapport Markdown récapitulatif, trié par
sévérité, avec plan de remédiation.

**API de démonstration** (`src/demo_api.py`) — endpoint protégé validant les
jetons OIDC de Keycloak : signature RS256 via JWKS, émetteur, audience et
expiration, plus autorisation par appartenance à un groupe.

---

## Jeu de données de test

`db/02-seed.sql` peuple 15 identités réparties sur trois populations
(employés, prestataires, partenaires), avec **quatre anomalies
volontairement implantées** (un départ non traité, un contrat expiré actif,
une violation de séparation des tâches, une mobilité non traitée). Ce jeu de
données sert de fixture de test : la suite d'intégration vérifie que les
quatre anomalies sont détectées avant remédiation (`pytest -m pre_sync`) puis
qu'elles ont disparu après un cycle `sync` complet (`pytest -m post_sync`).
C'est la preuve exécutable que le moteur fonctionne, pas une simple
affirmation.

---

## Tests et CI

26 tests (unitaires + intégration), dont une majorité de cas négatifs :
un sortant n'obtient aucun droit, une règle SoD ne se déclenche pas sur une
personne qui n'en détient qu'une moitié, une réexécution du provisioning ne
crée pas de doublon (idempotence).

Le pipeline `.github/workflows/ci.yml` exécute : lint et typage (ruff,
mypy), analyse de sécurité statique (Bandit), scan de secrets (gitleaks),
tests unitaires, puis un test de bout en bout complet (stack Docker, cycle
JML, détection des anomalies, réconciliation).

---

## Limites connues

- Aucun chiffrement TLS entre les composants ; environnement de laboratoire.
- Les mots de passe de service sont dans `.env`, non dans un coffre.
- L'annuaire OpenLDAP n'est pas un Active Directory ; les mécanismes
  Kerberos et les GPO ne sont pas couverts.
- La dormance des comptes est approximée à partir du journal de
  provisioning, faute de collecte des événements d'authentification.

---

*Projet personnel — LAGRINI Mohamed Abdellah*
