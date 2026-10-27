USE municipal_me;

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

INSERT INTO permissions (permission_key, description) VALUES
    ('progress_reports.submit', 'Submit progress updates for assigned projects'),
    ('progress_reports.view_all', 'View progress reports across all projects'),
    ('progress_reports.review', 'Review submitted progress reports and recommend them to the Municipal Board or request changes')
ON DUPLICATE KEY UPDATE description = VALUES(description);

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'project_manager' AND p.permission_key = 'progress_reports.submit';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'municipal_manager' AND p.permission_key IN ('progress_reports.view_all', 'progress_reports.review');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'municipality_admin' AND p.permission_key = 'progress_reports.view_all';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'auditor' AND p.permission_key = 'progress_reports.view_all';
