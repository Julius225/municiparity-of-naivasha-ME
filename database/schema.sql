CREATE DATABASE IF NOT EXISTS municipal_me CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE municipal_me;

CREATE TABLE IF NOT EXISTS installation_state (
    id TINYINT UNSIGNED NOT NULL,
    setup_completed TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT chk_installation_state_singleton CHECK (id = 1)
) ENGINE=InnoDB;

INSERT IGNORE INTO installation_state (id, setup_completed) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS roles (
    id SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(60) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_name (name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS permissions (
    id SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
    permission_key VARCHAR(100) NOT NULL,
    description VARCHAR(180) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_permissions_key (permission_key)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id SMALLINT UNSIGNED NOT NULL,
    permission_id SMALLINT UNSIGNED NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles (id),
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    role_id SMALLINT UNSIGNED NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(190) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_by BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email),
    KEY idx_users_role_active (role_id, is_active),
    CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles (id),
    CONSTRAINT fk_users_creator FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS projects (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_code VARCHAR(40) NOT NULL,
    title VARCHAR(180) NOT NULL,
    description TEXT NULL,
    department VARCHAR(150) NULL,
    location VARCHAR(180) NULL,
    status ENUM('planned', 'active', 'closed') NOT NULL DEFAULT 'planned',
    project_manager_id BIGINT UNSIGNED NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_projects_code (project_code),
    KEY idx_projects_manager (project_manager_id),
    CONSTRAINT fk_projects_manager FOREIGN KEY (project_manager_id) REFERENCES users (id),
    CONSTRAINT fk_projects_creator FOREIGN KEY (created_by) REFERENCES users (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS project_progress_reports (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    reported_by BIGINT UNSIGNED NOT NULL,
    reporting_date DATE NOT NULL,
    percent_complete DECIMAL(5,2) NOT NULL,
    work_completed TEXT NOT NULL,
    challenges TEXT NULL,
    next_steps TEXT NULL,
    review_status ENUM('submitted', 'changes_requested', 'recommended_for_board') NOT NULL DEFAULT 'submitted',
    review_note TEXT NULL,
    reviewed_by BIGINT UNSIGNED NULL,
    reviewed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_progress_project_date (project_id, reporting_date),
    KEY idx_progress_status_created (review_status, created_at),
    KEY idx_progress_reporter_created (reported_by, created_at),
    CONSTRAINT fk_progress_project FOREIGN KEY (project_id) REFERENCES projects (id),
    CONSTRAINT fk_progress_reporter FOREIGN KEY (reported_by) REFERENCES users (id),
    CONSTRAINT fk_progress_reviewer FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_progress_percent CHECK (percent_complete >= 0 AND percent_complete <= 100)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS project_budgets (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    financial_year SMALLINT UNSIGNED NOT NULL,
    funding_source VARCHAR(180) NOT NULL,
    approved_amount DECIMAL(15,2) NOT NULL,
    recorded_by BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_project_budget_source_year (project_id, financial_year, funding_source),
    UNIQUE KEY uq_project_budget_id_project (id, project_id),
    KEY idx_project_budgets_year (financial_year, project_id),
    CONSTRAINT fk_project_budgets_project FOREIGN KEY (project_id) REFERENCES projects (id),
    CONSTRAINT fk_project_budgets_recorder FOREIGN KEY (recorded_by) REFERENCES users (id),
    CONSTRAINT chk_project_budget_positive CHECK (approved_amount > 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS project_expenditures (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    budget_id BIGINT UNSIGNED NULL,
    expenditure_date DATE NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    category VARCHAR(100) NOT NULL,
    supplier VARCHAR(180) NULL,
    reference VARCHAR(120) NULL,
    description TEXT NULL,
    recorded_by BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_project_expenditures_project_date (project_id, expenditure_date),
    KEY idx_project_expenditures_budget (budget_id, project_id),
    CONSTRAINT fk_project_expenditures_project FOREIGN KEY (project_id) REFERENCES projects (id),
    CONSTRAINT fk_project_expenditures_budget_project FOREIGN KEY (budget_id, project_id)
        REFERENCES project_budgets (id, project_id),
    CONSTRAINT fk_project_expenditures_recorder FOREIGN KEY (recorded_by) REFERENCES users (id),
    CONSTRAINT chk_project_expenditure_positive CHECK (amount > 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS procurement_records (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    title VARCHAR(180) NOT NULL,
    procurement_method ENUM('open_tender', 'request_for_quotations', 'direct_procurement', 'framework', 'other') NOT NULL,
    stage ENUM('planned', 'advertised', 'evaluation', 'award_pending', 'awarded', 'contract_active', 'completed', 'cancelled') NOT NULL DEFAULT 'planned',
    supplier VARCHAR(180) NULL,
    reference VARCHAR(120) NULL,
    estimated_amount DECIMAL(15,2) NULL,
    contract_amount DECIMAL(15,2) NULL,
    planned_date DATE NULL,
    award_date DATE NULL,
    notes TEXT NULL,
    recorded_by BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_procurement_project_stage (project_id, stage),
    KEY idx_procurement_reference (reference),
    CONSTRAINT fk_procurement_project FOREIGN KEY (project_id) REFERENCES projects (id),
    CONSTRAINT fk_procurement_recorder FOREIGN KEY (recorded_by) REFERENCES users (id),
    CONSTRAINT chk_procurement_estimated_nonnegative CHECK (estimated_amount IS NULL OR estimated_amount >= 0),
    CONSTRAINT chk_procurement_contract_nonnegative CHECK (contract_amount IS NULL OR contract_amount >= 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS project_documents (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    storage_name VARCHAR(48) NOT NULL,
    media_type VARCHAR(50) NOT NULL,
    size_bytes INT UNSIGNED NOT NULL,
    sha256 CHAR(64) NOT NULL,
    description VARCHAR(500) NULL,
    uploaded_by BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_project_documents_storage_name (storage_name),
    KEY idx_project_documents_project_created (project_id, created_at),
    CONSTRAINT fk_project_documents_project FOREIGN KEY (project_id) REFERENCES projects (id),
    CONSTRAINT fk_project_documents_uploader FOREIGN KEY (uploaded_by) REFERENCES users (id),
    CONSTRAINT chk_project_documents_size CHECK (size_bytes > 0 AND size_bytes <= 10485760)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NULL,
    event_key VARCHAR(100) NOT NULL,
    record_id BIGINT UNSIGNED NULL,
    details JSON NOT NULL,
    ip_address VARCHAR(45) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_event_created (event_key, created_at),
    KEY idx_audit_user_created (user_id, created_at),
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_hash CHAR(64) NOT NULL,
    attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_login_attempt_ip_time (ip_hash, attempted_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS password_reset_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_hash CHAR(64) NOT NULL,
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_password_reset_ip_time (ip_hash, requested_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_password_reset_token_hash (token_hash),
    KEY idx_password_reset_user_expiry (user_id, expires_at, used_at),
    CONSTRAINT fk_password_reset_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB;

INSERT INTO roles (name, display_name) VALUES
    ('municipality_admin', 'Municipality Administrator'),
    ('municipal_manager', 'Municipal Manager'),
    ('project_manager', 'Project Manager'),
    ('me_officer', 'M&E Officer'),
    ('finance_officer', 'Finance Officer'),
    ('procurement_officer', 'Procurement Officer'),
    ('auditor', 'Auditor')
ON DUPLICATE KEY UPDATE display_name = VALUES(display_name);

INSERT INTO permissions (permission_key, description) VALUES
    ('users.manage', 'Create users and deactivate accounts'),
    ('projects.view', 'View project records'),
    ('projects.create', 'Create and assign projects'),
    ('projects.assign', 'Reassign projects to project managers'),
    ('projects.update', 'Update project details'),
    ('projects.view_all', 'View all projects regardless of assignment'),
    ('progress_reports.submit', 'Submit progress updates for assigned projects'),
    ('progress_reports.view_all', 'View progress reports across all projects'),
    ('progress_reports.review', 'Review submitted progress reports and recommend them to the Municipal Board or request changes'),
    ('finance.view', 'View project budgets and expenditure'),
    ('finance.manage', 'Record project budgets and expenditure'),
    ('procurement.view', 'View project procurement records'),
    ('procurement.manage', 'Record project procurement details'),
    ('documents.view', 'View private project evidence documents'),
    ('documents.upload', 'Upload private project evidence documents'),
    ('audit_logs.view', 'View the audit log')
ON DUPLICATE KEY UPDATE description = VALUES(description);

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'municipality_admin';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'municipal_manager' AND p.permission_key IN ('progress_reports.view_all', 'progress_reports.review');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'municipality_admin' AND p.permission_key = 'progress_reports.view_all';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'auditor' AND p.permission_key = 'progress_reports.view_all';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'project_manager' AND p.permission_key = 'projects.update';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'project_manager' AND p.permission_key = 'progress_reports.submit';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'municipal_manager' AND p.permission_key IN ('projects.view', 'projects.view_all');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'project_manager' AND p.permission_key IN ('projects.view', 'projects.create');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('me_officer', 'finance_officer', 'procurement_officer', 'auditor')
AND p.permission_key IN ('projects.view', 'projects.view_all');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'auditor' AND p.permission_key = 'audit_logs.view';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('municipal_manager', 'me_officer', 'finance_officer', 'procurement_officer', 'auditor')
  AND p.permission_key IN ('finance.view', 'procurement.view');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'finance_officer' AND p.permission_key = 'finance.manage';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'procurement_officer' AND p.permission_key = 'procurement.manage';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('municipal_manager', 'me_officer', 'project_manager', 'auditor')
  AND p.permission_key = 'documents.view';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('me_officer', 'project_manager')
  AND p.permission_key = 'documents.upload';
