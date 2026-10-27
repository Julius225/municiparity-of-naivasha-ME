USE municipal_me;

INSERT INTO permissions (permission_key, description)
VALUES ('projects.update', 'Update project details')
ON DUPLICATE KEY UPDATE description = VALUES(description);

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name IN ('municipality_admin', 'project_manager')
  AND p.permission_key = 'projects.update';
