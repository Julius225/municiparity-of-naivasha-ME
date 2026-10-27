# Municipal Project Monitoring and Evaluation System

This is the first implementation slice for one municipality installation. Each municipality should use its own deployment, `.env` configuration, MySQL database, private file storage and backups.

## Included in this first milestone

- PDO connection to MySQL using settings from the project-root `.env` file.
- One-time initial administrator setup protected by a configured setup key.
- Password-based sign-in, sign-out, idle session timeout, CSRF protection, login throttling and expiring single-use email password-reset links.
- Role-based server-side access checks and administrator-managed accounts.
- Account deactivation without deleting the account or its history.
- Project creation, project-manager assignment and reassignment.
- A Project Register with project detail pages, searchable/filterable lists and audited detail edits.
- Project progress reports, Municipal Manager review, and recommendation to the Municipal Board (not final Board approval).
- Role-controlled project budgets, expenditure, procurement-stage tracking and private evidence attachments, with audit events and dashboard budget totals.
- Permission-checked CSV exports for the project register, progress reports, budgets, expenditure and procurement.
- Audit events for important authentication, account and project actions.
- Responsive application shell with role-filtered sidebar navigation, global project search, project register filters/sorting/pagination, and real-record dashboard summaries.
- Project workspaces with functional Overview and Progress sections for implemented project and reporting features.

PDF report generation, formal Municipal Board decisions and county budget approvals are not implemented. Finance and procurement records are operational tracking only; they do not constitute appropriations, payment authorization, or procurement award approval.

## Requirements

- PHP 8.0 or later with PDO MySQL enabled.
- MySQL 8.0+ (the schema uses the MySQL JSON type).
- Apache with `mod_rewrite` enabled if using the included rewrite protections.

## Local setup with XAMPP

1. Start Apache and MySQL from the XAMPP control panel.
2. Import `database/schema.sql` using phpMyAdmin or the MySQL command-line client. The script creates the `municipal_me` database and the initial role/permission catalogue.
3. Copy `.env.example` to `.env`. Configure `DB_NAME`, `DB_USER` and `DB_PASSWORD` for the database. Generate a setup key with `C:\xampp\php\php.exe -r "echo bin2hex(random_bytes(32)), PHP_EOL;"` and set the output as `MUNI_SETUP_KEY` before opening the setup page. The setup page will not accept the example placeholder or a key shorter than 32 characters.
4. Prefer an Apache virtual host whose document root is the project's `public` directory. For a simple local XAMPP installation, open `http://localhost/muniparity%20of%20Naivasha%20ME/public/`.
5. Complete the one-time setup page to create the first Municipality Administrator. The setup page closes automatically once that account exists.
6. Sign in, create Project Manager accounts from **Users**, then create projects and assign them to those managers. Open a project title to view its details, or use **Edit** to update its title, description, department and location. Reassign a manager's projects before deactivating that account.
7. For an existing installation, apply `database/migrations/003_project_progress_reporting.sql`. Project Managers can then submit reports from their assigned project pages. Municipal Managers can request changes or recommend a report for Municipal Board consideration from **Progress reports**. The recommendation is not a final Board approval; confirm Naivasha's current delegation and appointment instruments before configuring formal approval authority.
8. For an existing installation, apply `database/migrations/004_password_reset_tokens.sql` (fresh installations include these tables in `schema.sql`). Configure `APP_URL` to the application's public URL and `MAIL_FROM` to an address handled by the server's outgoing mail transport. Users can then use **Forgot your password?** on the sign-in page. Reset requests have a neutral response, an IP-based rate limit, and single-use tokens that expire after 60 minutes. A configured sender address alone does not configure PHP mail delivery; verify delivery with your hosting provider before relying on account recovery.
9. For an existing installation, apply `database/migrations/005_finance_procurement.sql`. Finance Officers can record project budgets and expenditure; Procurement Officers can record procurement stages. Municipal Managers, M&E Officers and Auditors can view the records, and administrators can manage both modules. Amounts are recorded in KES. A fresh installation includes these tables in the base schema.
10. For an existing installation, apply `database/migrations/006_project_evidence_documents.sql`. Administrators, Project Managers and M&E Officers can upload project evidence; users with document-view permission can download it only within their project access. Uploads accept PDF, JPEG and PNG up to 10 MB and are stored outside `public`. Enable PHP Fileinfo and set `upload_max_filesize` and `post_max_size` to at least 10 MB (a slightly higher `post_max_size` is recommended). Project, progress, budget, expenditure and procurement registers have permission-checked CSV exports that open in spreadsheet software; PDF exports are not included.

For an existing installation, run `database/migrations/002_project_register_update_permission.sql` against that municipality's database to grant project-detail editing to administrators and project managers. The existing `projects` table needs no structural changes for this feature.

### Production and backups

When `APP_ENV=production`, the application blocks requests until `APP_DEBUG=false`, an absolute HTTPS `APP_URL`, a valid `MAIL_FROM`, and non-root database credentials with a non-empty password are configured. Use a dedicated, least-privilege database account and configure TLS at the web server. `.env`, logs, backup archives and private evidence are excluded from Git; keep them outside the public document root. After first-admin setup is complete, remove `MUNI_SETUP_KEY` from `.env`. Treat any setup key previously shared or uploaded as compromised.

On Windows/XAMPP, `scripts/backup.ps1` creates a timestamped ZIP containing a MySQL dump and private storage contents under `BACKUP_DIR`, and restricts the backup directory to the current Windows account. Run it manually with `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\backup.ps1`, or register a daily task with `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\register-backup-task.ps1 -Time 02:00`. If Windows denies registration, rerun from an elevated PowerShell window. `scripts/restore.ps1 -ArchivePath <backup.zip>` requires typing a database-specific confirmation, makes a safety backup, replaces database tables, and preserves existing private files alongside the restored set. Test restore procedures on a separate staging installation before relying on them. Backups on the same disk are not disaster recovery: encrypt them and copy them to an access-controlled off-site location; periodically test a full restore.

Production configuration checks do not install TLS, configure the PHP mail transport, create MySQL grants, encrypt backups, or schedule jobs automatically. These are deployment-owner responsibilities.

## Initial roles

- Municipality Administrator: manage user accounts and create/reassign/update projects; view projects and audit history.
- Municipal Manager: oversee all projects; review submitted progress updates, request changes, or recommend an update for Municipal Board consideration.
- Project Manager: view and update assigned projects, and create projects assigned to their own account.
- M&E Officer, Finance Officer and Procurement Officer: read-only project access in this initial slice.
- Auditor: read-only project and audit-log access.

Permissions are stored in `permissions` and `role_permissions`; hiding a navigation link is not used as the authorization boundary. Search filters include project code, title, department and manager, plus exact department and status filters. Project code, manager assignment and status are intentionally not editable from the project-details form. Progress reports are auditable; the Municipal Manager can request changes or recommend a report for Board consideration, while formal Board approval remains outside this initial workflow.

## Naivasha governance alignment

The workflow distinguishes operational review from formal municipal decisions. Under the [Urban Areas and Cities Act](https://new.kenyalaw.org/akn/ke/act/2011/13/eng@2022-12-31), the Municipal Manager implements Municipal Board decisions and is answerable to the Board. The app therefore labels a manager's positive review as a **recommendation for Board consideration**, not as Board approval. The Board's plan and budget proposals follow county processes, including County Treasury and County Assembly responsibilities described in the Act and the [County Governments Act](https://new.kenyalaw.org/akn/ke/act/2012/17/eng@2022-12-31). Confirm current Nakuru County delegations and Naivasha appointment instruments before adding formal approval actions, thresholds, or Board-member accounts.

## Important next steps

Before using this with real records, configure HTTPS, set a strong database account instead of the XAMPP root account, configure and test outgoing email for account recovery, register the backup schedule with an authorized Windows account, and establish encrypted off-site copies. Confirm the Municipal Manager's approval responsibilities and the municipality's finance/procurement workflows with the relevant authorities. Run role-based acceptance tests and a full restore drill before go-live.
