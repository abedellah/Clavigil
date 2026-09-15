-- ---------------------------------------------------------------------------
-- Entitlement catalogue
-- ---------------------------------------------------------------------------
INSERT INTO entitlement (entitlement_id, application, display_name, description, risk_level, is_privileged) VALUES
('ERP_READ',      'ERP',      'Consultation',        'Lecture des donnees comptables',              'low',      false),
('ERP_POST',      'ERP',      'Saisie ecritures',    'Creation d''ecritures comptables',            'medium',   false),
('ERP_VALIDATE',  'ERP',      'Validation paiement', 'Validation et emission des paiements',        'critical', true),
('ERP_ADMIN',     'ERP',      'Administration',      'Administration fonctionnelle de l''ERP',      'critical', true),
('CRM_READ',      'CRM',      'Consultation',        'Lecture du portefeuille client',              'low',      false),
('CRM_WRITE',     'CRM',      'Modification',        'Modification des fiches client',              'medium',   false),
('CRM_EXPORT',    'CRM',      'Export de masse',     'Export complet de la base client',            'high',     false),
('AD_HELPDESK',   'AD',       'Reset mot de passe',  'Reinitialisation des mots de passe',          'high',     true),
('AD_DOMAIN_ADM', 'AD',       'Admin du domaine',    'Administration complete de l''annuaire',      'critical', true),
('VPN_STANDARD',  'VPN',      'Acces distant',       'Acces VPN standard',                          'medium',   false);

-- ---------------------------------------------------------------------------
-- Business roles
-- ---------------------------------------------------------------------------
INSERT INTO business_role (role_id, display_name, description, is_birthright, auto_department, auto_population) VALUES
('R_BASE_EMP',    'Socle employe',        'Acces de base accorde a tout employe',            true,  NULL,          'employee'),
('R_BASE_EXT',    'Socle externe',        'Acces de base prestataire ou partenaire',         true,  NULL,          'external'),
('R_COMPTA',      'Comptabilite',         'Saisie comptable courante',                       true,  'Comptabilite', NULL),
('R_TRESORERIE',  'Tresorerie',           'Validation et emission des paiements',            false, NULL,          NULL),
('R_COMMERCIAL',  'Commercial',           'Gestion du portefeuille client',                  true,  'Commercial',   NULL),
('R_SUPPORT_IT',  'Support informatique', 'Support de premier niveau',                       true,  'IT',           NULL),
('R_ADMIN_AD',    'Administrateur AD',    'Administration de l''annuaire d''entreprise',     false, NULL,          NULL),
('R_ADMIN_ERP',   'Administrateur ERP',   'Administration fonctionnelle de l''ERP',          false, NULL,          NULL);

INSERT INTO role_entitlement (role_id, entitlement_id) VALUES
('R_BASE_EMP',   'VPN_STANDARD'),
('R_BASE_EXT',   'VPN_STANDARD'),
('R_COMPTA',     'ERP_READ'),
('R_COMPTA',     'ERP_POST'),
('R_TRESORERIE', 'ERP_READ'),
('R_TRESORERIE', 'ERP_VALIDATE'),
('R_COMMERCIAL', 'CRM_READ'),
('R_COMMERCIAL', 'CRM_WRITE'),
('R_SUPPORT_IT', 'AD_HELPDESK'),
('R_ADMIN_AD',   'AD_DOMAIN_ADM'),
('R_ADMIN_ERP',  'ERP_ADMIN'),
('R_ADMIN_ERP',  'CRM_EXPORT');

-- ---------------------------------------------------------------------------
-- Segregation of duties rules
-- ---------------------------------------------------------------------------
INSERT INTO sod_rule (rule_id, role_a, role_b, severity, rationale) VALUES
('SOD_01', 'R_COMPTA',    'R_TRESORERIE', 'high',
 'Saisir une ecriture et valider son paiement permet un detournement sans controle.'),
('SOD_02', 'R_ADMIN_AD',  'R_SUPPORT_IT', 'medium',
 'Le support ne doit pas cumuler la reinitialisation de mots de passe et l''administration du domaine.'),
('SOD_03', 'R_ADMIN_ERP', 'R_TRESORERIE', 'high',
 'Administrer l''ERP et valider les paiements permet de modifier les controles applicatifs.');

-- ---------------------------------------------------------------------------
-- Population. Managers first so the self-references resolve.
-- ---------------------------------------------------------------------------
INSERT INTO hr_person (person_id, first_name, last_name, email, population, department, job_title, manager_id, sponsor_id, contract_start, contract_end, hr_status) VALUES
('P0001', 'Nadia',   'Benali',    'nadia.benali@demo.local',    'employee', 'Direction',     'Directrice generale',      NULL,    NULL, '2015-03-02', NULL, 'active'),
('P0002', 'Karim',   'Alaoui',    'karim.alaoui@demo.local',    'employee', 'Comptabilite',  'Responsable comptable',    'P0001', NULL, '2017-09-11', NULL, 'active'),
('P0003', 'Sofia',   'Marchand',  'sofia.marchand@demo.local',  'employee', 'IT',            'Responsable IT',           'P0001', NULL, '2016-01-18', NULL, 'active'),
('P0004', 'Youssef', 'Idrissi',   'youssef.idrissi@demo.local', 'employee', 'Commercial',    'Directeur commercial',     'P0001', NULL, '2018-06-04', NULL, 'active');

INSERT INTO hr_person (person_id, first_name, last_name, email, population, department, job_title, manager_id, sponsor_id, contract_start, contract_end, hr_status) VALUES
('P0005', 'Leila',   'Fassi',     'leila.fassi@demo.local',     'employee',   'Comptabilite', 'Comptable',              'P0002', NULL,    '2021-02-15', NULL,         'active'),
('P0006', 'Mehdi',   'Tazi',      'mehdi.tazi@demo.local',      'employee',   'Tresorerie',   'Tresorier',              'P0002', NULL,    '2020-11-03', NULL,         'active'),
('P0007', 'Ines',    'Roux',      'ines.roux@demo.local',       'employee',   'IT',           'Technicien support',     'P0003', NULL,    '2022-04-25', NULL,         'active'),
('P0008', 'Omar',    'Cherkaoui', 'omar.cherkaoui@demo.local',  'employee',   'IT',           'Administrateur systeme', 'P0003', NULL,    '2019-08-19', NULL,         'active'),
('P0009', 'Camille', 'Perrin',    'camille.perrin@demo.local',  'employee',   'Commercial',   'Charge de clientele',    'P0004', NULL,    '2023-01-09', NULL,         'active'),
('P0010', 'Rachid',  'Bennani',   'rachid.bennani@demo.local',  'contractor', 'IT',           'Consultant infra',       'P0003', NULL,    '2025-09-01', '2027-08-31', 'active'),
('P0011', 'Anouk',   'Lemaire',   'anouk.lemaire@demo.local',   'contractor', 'Commercial',   'Consultante CRM',        'P0004', NULL,    '2026-01-12', '2027-06-30', 'active'),
('P0012', 'Thomas',  'Girard',    'thomas.girard@demo.local',   'partner',    'Commercial',   'Partenaire revendeur',   NULL,    'P0004', '2025-05-01', '2027-04-30', 'active'),
('P0013', 'Salma',   'Ouazzani',  'salma.ouazzani@demo.local',  'employee',   'Commercial',   'Charge de clientele',    'P0004', NULL,    '2019-03-11', NULL,         'terminated'),
('P0014', 'Hugo',    'Bertrand',  'hugo.bertrand@demo.local',   'contractor', 'Comptabilite', 'Consultant ERP',         'P0002', NULL,    '2024-02-05', '2025-12-31', 'active'),
('P0015', 'Amine',   'Saidi',     'amine.saidi@demo.local',     'employee',   'Comptabilite', 'Controleur de gestion',  'P0002', NULL,    '2020-07-20', NULL,         'active');

-- ---------------------------------------------------------------------------
-- Current assignments.
--
-- Four anomalies are planted deliberately. Your reconciliation report must find
-- all four without being told where they are. Do not read past this line if you
-- want to test yourself honestly.
--
--   1. P0013 is terminated in HR but still holds active roles  (leaver failure)
--   2. P0014's contract ended 2025-12-31 but is still 'active' (expiry failure)
--   3. P0015 holds R_COMPTA and R_TRESORERIE together          (SOD_01 breach)
--   4. P0009 moved from Comptabilite to Commercial and kept    (mover failure)
--      the accounting role alongside the commercial one
-- ---------------------------------------------------------------------------
INSERT INTO role_assignment (person_id, role_id, granted_by) VALUES
('P0001', 'R_BASE_EMP',   'birthright'),
('P0002', 'R_BASE_EMP',   'birthright'),
('P0002', 'R_COMPTA',     'birthright'),
('P0003', 'R_BASE_EMP',   'birthright'),
('P0003', 'R_SUPPORT_IT', 'birthright'),
('P0004', 'R_BASE_EMP',   'birthright'),
('P0004', 'R_COMMERCIAL', 'birthright'),
('P0005', 'R_BASE_EMP',   'birthright'),
('P0005', 'R_COMPTA',     'birthright'),
('P0006', 'R_BASE_EMP',   'birthright'),
('P0006', 'R_TRESORERIE', 'P0002'),
('P0007', 'R_BASE_EMP',   'birthright'),
('P0007', 'R_SUPPORT_IT', 'birthright'),
('P0008', 'R_BASE_EMP',   'birthright'),
('P0008', 'R_SUPPORT_IT', 'birthright'),
('P0008', 'R_COMMERCIAL', 'P0003'),
('P0009', 'R_BASE_EMP',   'birthright'),
('P0009', 'R_COMMERCIAL', 'birthright'),
('P0009', 'R_COMPTA',     'birthright'),
('P0010', 'R_BASE_EXT',   'birthright'),
('P0010', 'R_SUPPORT_IT', 'P0003'),
('P0011', 'R_BASE_EXT',   'birthright'),
('P0011', 'R_COMMERCIAL', 'P0004'),
('P0012', 'R_BASE_EXT',   'birthright'),
('P0012', 'R_COMMERCIAL', 'P0004'),
('P0013', 'R_BASE_EMP',   'birthright'),
('P0013', 'R_COMMERCIAL', 'birthright'),
('P0014', 'R_BASE_EXT',   'birthright'),
('P0014', 'R_COMPTA',     'P0002'),
('P0015', 'R_BASE_EMP',   'birthright'),
('P0015', 'R_COMPTA',     'birthright'),
('P0015', 'R_TRESORERIE', 'P0002');
