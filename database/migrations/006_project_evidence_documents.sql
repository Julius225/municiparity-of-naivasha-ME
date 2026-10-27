USE municipal_me;

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

INSERT INTO permissions (permission_key, description) VALUES
    ('documents.view', 'View private project evidence documents'),
    ('documents.upload', 'Upload private project evidence documents')
ON DUPLICATE KEY UPDATE description = VALUES(description);

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('municipality_admin', 'municipal_manager', 'me_officer', 'project_manager', 'auditor')
  AND p.permission_key = 'documents.view';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('municipality_admin', 'me_officer', 'project_manager')
  AND p.permission_key = 'documents.upload';
