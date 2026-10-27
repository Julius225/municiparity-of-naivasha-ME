USE municipal_me;

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

INSERT INTO permissions (permission_key, description) VALUES
    ('finance.view', 'View project budgets and expenditure'),
    ('finance.manage', 'Record project budgets and expenditure'),
    ('procurement.view', 'View project procurement records'),
    ('procurement.manage', 'Record project procurement details')
ON DUPLICATE KEY UPDATE description = VALUES(description);

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('municipality_admin', 'municipal_manager', 'me_officer', 'finance_officer', 'procurement_officer', 'auditor')
  AND p.permission_key IN ('finance.view', 'procurement.view');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('municipality_admin', 'finance_officer')
  AND p.permission_key = 'finance.manage';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('municipality_admin', 'procurement_officer')
  AND p.permission_key = 'procurement.manage';
