-- Keycloak needs its own database in the same instance.
CREATE DATABASE keycloak;

-- ---------------------------------------------------------------------------
-- HR system — the source of authority for identities.
-- Nothing else in the lab is allowed to create an identity.
-- ---------------------------------------------------------------------------
CREATE TABLE hr_person (
    person_id       TEXT PRIMARY KEY,
    first_name      TEXT        NOT NULL,
    last_name       TEXT        NOT NULL,
    email           TEXT        NOT NULL UNIQUE,
    population      TEXT        NOT NULL
                    CHECK (population IN ('employee', 'contractor', 'partner')),
    department      TEXT        NOT NULL,
    job_title       TEXT        NOT NULL,
    manager_id      TEXT        REFERENCES hr_person (person_id),
    sponsor_id      TEXT        REFERENCES hr_person (person_id),
    contract_start  DATE        NOT NULL,
    contract_end    DATE,
    hr_status       TEXT        NOT NULL DEFAULT 'active'
                    CHECK (hr_status IN ('active', 'suspended', 'terminated')),
    -- Filled in by the provisioning engine when the account is created.
    -- This column is the link between an HR record and its accounts.
    account_uid     TEXT        UNIQUE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Contractors and partners must be time-bounded; employees need not be.
ALTER TABLE hr_person ADD CONSTRAINT hr_person_end_date_required
    CHECK (population = 'employee' OR contract_end IS NOT NULL);

-- Partners are sponsored by an internal person.
ALTER TABLE hr_person ADD CONSTRAINT hr_person_sponsor_required
    CHECK (population <> 'partner' OR sponsor_id IS NOT NULL);

-- ---------------------------------------------------------------------------
-- Entitlement catalogue — the fine-grained permissions in target applications.
-- ---------------------------------------------------------------------------
CREATE TABLE entitlement (
    entitlement_id  TEXT PRIMARY KEY,
    application     TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    description     TEXT NOT NULL,
    risk_level      TEXT NOT NULL DEFAULT 'low'
                    CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    is_privileged   BOOLEAN NOT NULL DEFAULT false
);

-- ---------------------------------------------------------------------------
-- Role model — business roles aggregate entitlements. Birthright roles are
-- granted automatically by the lifecycle engine; the rest require a request.
-- ---------------------------------------------------------------------------
CREATE TABLE business_role (
    role_id         TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    description     TEXT NOT NULL,
    is_birthright   BOOLEAN NOT NULL DEFAULT false,
    auto_department TEXT,
    auto_population TEXT
);

CREATE TABLE role_entitlement (
    role_id         TEXT REFERENCES business_role (role_id) ON DELETE CASCADE,
    entitlement_id  TEXT REFERENCES entitlement (entitlement_id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, entitlement_id)
);

-- ---------------------------------------------------------------------------
-- Assignments — what a person currently holds, and why.
-- ---------------------------------------------------------------------------
CREATE TABLE role_assignment (
    assignment_id   BIGSERIAL PRIMARY KEY,
    person_id       TEXT NOT NULL REFERENCES hr_person (person_id),
    role_id         TEXT NOT NULL REFERENCES business_role (role_id),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by      TEXT NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revocation_note TEXT,
    UNIQUE (person_id, role_id, granted_at)
);

CREATE INDEX idx_role_assignment_person ON role_assignment (person_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Segregation of duties — pairs of roles nobody may hold simultaneously.
-- ---------------------------------------------------------------------------
CREATE TABLE sod_rule (
    rule_id         TEXT PRIMARY KEY,
    role_a          TEXT NOT NULL REFERENCES business_role (role_id),
    role_b          TEXT NOT NULL REFERENCES business_role (role_id),
    severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    rationale       TEXT NOT NULL,
    CHECK (role_a < role_b)
);

-- ---------------------------------------------------------------------------
-- Provisioning audit trail — every action the engine takes against a target.
-- ---------------------------------------------------------------------------
CREATE TABLE provisioning_log (
    log_id          BIGSERIAL PRIMARY KEY,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    person_id       TEXT,
    target_system   TEXT NOT NULL,
    action          TEXT NOT NULL,
    detail          TEXT,
    outcome         TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'skipped')),
    error_message   TEXT
);

CREATE INDEX idx_provisioning_log_occurred ON provisioning_log (occurred_at DESC);
CREATE INDEX idx_provisioning_log_person   ON provisioning_log (person_id);

-- ---------------------------------------------------------------------------
-- Access certification campaigns.
-- ---------------------------------------------------------------------------
CREATE TABLE certification_campaign (
    campaign_id     TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at       TIMESTAMPTZ,
    scope_note      TEXT NOT NULL
);

CREATE TABLE certification_item (
    item_id         BIGSERIAL PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES certification_campaign (campaign_id),
    person_id       TEXT NOT NULL REFERENCES hr_person (person_id),
    role_id         TEXT NOT NULL REFERENCES business_role (role_id),
    reviewer_id     TEXT NOT NULL REFERENCES hr_person (person_id),
    decision        TEXT CHECK (decision IN ('approve', 'revoke')),
    decided_at      TIMESTAMPTZ,
    justification   TEXT
);
