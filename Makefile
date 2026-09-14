.PHONY: help up down logs init sync reconcile report ldap-users ldap-groups ldap-orphan api test lint clean

help:                ## Show this help
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

up:                  ## Start the stack
	docker compose up -d
	@echo "Keycloak http://localhost:8080"

down:                ## Stop the stack and remove volumes
	docker compose down -v

logs:                ## Follow container logs
	docker compose logs -f

init:                ## Create org units and groups in the targets
	python src/main.py init

sync:                ## Run the full JML cycle
	python src/main.py sync

reconcile:           ## Run all reconciliation checks
	python src/main.py reconcile

report:              ## Write the Markdown reconciliation report
	python src/main.py report

ldap-users:          ## List directory accounts (ldapsearch)
	docker exec iam-openldap ldapsearch -x -LLL \
		-D "cn=admin,dc=demo,dc=local" -w "$$LDAP_ADMIN_PASSWORD" \
		-b "ou=people,dc=demo,dc=local" "(objectClass=inetOrgPerson)" \
		uid cn mail title

ldap-groups:         ## List groups and their members (ldapsearch)
	docker exec iam-openldap ldapsearch -x -LLL \
		-D "cn=admin,dc=demo,dc=local" -w "$$LDAP_ADMIN_PASSWORD" \
		-b "ou=groups,dc=demo,dc=local" "(objectClass=groupOfNames)" \
		cn member

ldap-orphan:         ## Create an orphan account to test reconciliation
	docker exec -i iam-openldap ldapadd -x \
		-D "cn=admin,dc=demo,dc=local" -w "$$LDAP_ADMIN_PASSWORD" <<-'LDIF'
		dn: uid=ghost,ou=people,dc=demo,dc=local
		objectClass: inetOrgPerson
		uid: ghost
		cn: Compte Fantome
		sn: Fantome
		mail: ghost@demo.local
	LDIF

api:                 ## Run the protected demo API on port 5000
	python src/demo_api.py

test:                ## Run unit tests (no containers needed)
	pytest -v -m "not integration"

lint:                ## Lint, format check and type check
	ruff check src tests
	ruff format --check src tests
	mypy src

clean:               ## Remove caches and generated reports
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache reports/*/
