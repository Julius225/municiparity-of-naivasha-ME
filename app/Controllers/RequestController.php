<?php
declare(strict_types=1);

require dirname(__DIR__) . DIRECTORY_SEPARATOR . 'bootstrap.php';

$page = (string) ($_GET['page'] ?? 'dashboard');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$user = null;
$message = (string) ($_SESSION['flash'] ?? '');
unset($_SESSION['flash']);

try {
    $user = current_user();

    if ($config['production_errors'] !== []) {
        foreach ($config['production_errors'] as $configurationError) {
            error_log('Production configuration check failed: ' . $configurationError);
        }
        http_response_code(503);
        render_page(
            'Production configuration required',
            '<section class="card error"><p>Production security settings are incomplete. Contact the system administrator and check the server log.</p></section>'
        );
        exit;
    }

    if ($page === 'setup') {
        if (!is_first_setup_required()) {
            redirect('login', ['notice' => 'Setup is already complete.']);
        }
        if ($method === 'POST') {
            verify_csrf();
            if (!$config['setup_key_configured']) {
                throw new RuntimeException('Initial setup is unavailable until a strong MUNI_SETUP_KEY is configured in the root .env file.');
            }
            if (!hash_equals($config['setup_key'], (string) ($_POST['setup_key'] ?? ''))) {
                throw new RuntimeException('The setup key is incorrect or has not been configured.');
            }
            $name = trim((string) ($_POST['full_name'] ?? ''));
            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            $password = (string) ($_POST['password'] ?? '');
            $confirmation = (string) ($_POST['password_confirmation'] ?? '');
            if ($name === '' || strlen($name) > 150 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190) {
                throw new RuntimeException('Enter a valid name and email address.');
            }
            if (strlen($password) < 12 || $password !== $confirmation) {
                throw new RuntimeException('Use a password of at least 12 characters and ensure both password fields match.');
            }
            $pdo = db();
            $pdo->beginTransaction();
            try {
                $setupState = $pdo->query(
                    'SELECT setup_completed FROM installation_state WHERE id = 1 FOR UPDATE'
                )->fetchColumn();
                if ($setupState === false || (int) $setupState !== 0) {
                    throw new RuntimeException('Initial setup has already been completed.');
                }
                if (!is_first_setup_required()) {
                    throw new RuntimeException('Initial setup has already been completed.');
                }
                $roleStatement = $pdo->prepare('SELECT id FROM roles WHERE name = :name');
                $roleStatement->execute(['name' => 'municipality_admin']);
                $roleId = $roleStatement->fetchColumn();
                if (!$roleId) {
                    throw new RuntimeException('Roles are not installed. Import database/schema.sql first.');
                }
                $insert = $pdo->prepare(
                    'INSERT INTO users (role_id, full_name, email, password_hash)
                     VALUES (:role_id, :full_name, :email, :password_hash)'
                );
                $insert->execute([
                    'role_id' => (int) $roleId,
                    'full_name' => $name,
                    'email' => $email,
                    'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                ]);
                $newUserId = (int) $pdo->lastInsertId();
                $pdo->exec('UPDATE installation_state SET setup_completed = 1 WHERE id = 1');
                $_SESSION['user_id'] = $newUserId;
                $_SESSION['last_activity'] = time();
                session_regenerate_id(true);
                audit('setup.initial_admin_created', $newUserId);
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $exception;
            }
            redirect('dashboard');
        }
        if (!$config['setup_key_configured']) {
            $content = '<section class="card narrow"><p>Before creating the first administrator, configure a strong setup key in the project-root <code>.env</code> file. Generate one with:</p>'
                . '<p><code>C:\\xampp\\php\\php.exe -r "echo bin2hex(random_bytes(32)), PHP_EOL;"</code></p>'
                . '<p>Set the output as <code>MUNI_SETUP_KEY</code>, then reload this page. Do not use the example placeholder. Setup closes automatically after the first administrator is created.</p></section>';
        } else {
            $content = '<section class="card narrow"><p>One-time setup creates the first Municipality Administrator. Setup closes automatically after the first account is created.</p>'
                . '<form method="post" action="' . e(url('setup')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
                . '<label>Setup key<input type="password" name="setup_key" required autocomplete="off"></label>'
                . '<label>Administrator name<input name="full_name" maxlength="150" required autocomplete="name"></label>'
                . '<label>Email address<input type="email" name="email" maxlength="190" required autocomplete="email"></label>'
                . '<label>Password<input type="password" name="password" minlength="12" required autocomplete="new-password"></label>'
                . '<label>Confirm password<input type="password" name="password_confirmation" minlength="12" required autocomplete="new-password"></label>'
                . '<button type="submit">Create administrator</button></form></section>';
        }
        render_page('Initial setup', $content, null, $message);
        exit;
    }

    if ($page === 'logout') {
        if ($method !== 'POST') {
            http_response_code(405);
            throw new RuntimeException('Use the log out button to end your session.');
        }
        verify_csrf();
        if ($user) {
            audit('auth.logout');
        }
        logout_user();
        redirect('login');
    }

    if ($user && in_array($page, ['forgot_password', 'reset_password'], true)) {
        redirect('dashboard');
    }

    if ($page === 'forgot_password') {
        $confirmation = false;
        if ($method === 'POST') {
            verify_csrf();
            $ipHash = hash('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            $pdo = db();
            $pdo->prepare(
                'DELETE FROM password_reset_requests WHERE requested_at < DATE_SUB(NOW(), INTERVAL 1 DAY)'
            )->execute();
            $attempts = $pdo->prepare(
                'SELECT COUNT(*) FROM password_reset_requests
                 WHERE ip_hash = :ip_hash AND requested_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
            );
            $attempts->execute(['ip_hash' => $ipHash]);
            if ((int) $attempts->fetchColumn() >= 5) {
                throw new RuntimeException('Too many reset requests. Wait 15 minutes before trying again.');
            }
            $pdo->prepare('INSERT INTO password_reset_requests (ip_hash) VALUES (:ip_hash)')
                ->execute(['ip_hash' => $ipHash]);

            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190) {
                throw new RuntimeException('Enter a valid email address.');
            }
            if (!$config['password_reset_enabled']) {
                throw new RuntimeException('Password reset is unavailable. Contact the system administrator to configure the application URL and outgoing email.');
            }

            $accountQuery = $pdo->prepare(
                'SELECT id FROM users WHERE email = :email AND is_active = 1 LIMIT 1'
            );
            $accountQuery->execute(['email' => $email]);
            $accountId = $accountQuery->fetchColumn();
            if ($accountId !== false) {
                $token = bin2hex(random_bytes(32));
                $pdo->prepare(
                    'UPDATE password_reset_tokens SET used_at = NOW()
                     WHERE user_id = :user_id AND used_at IS NULL'
                )->execute(['user_id' => (int) $accountId]);
                $pdo->prepare(
                    'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
                     VALUES (:user_id, :token_hash, DATE_ADD(NOW(), INTERVAL 60 MINUTE))'
                )->execute([
                    'user_id' => (int) $accountId,
                    'token_hash' => hash('sha256', $token),
                ]);
                audit('auth.password_reset_requested', (int) $accountId);
                if (!send_password_reset_email($email, $token)) {
                    $pdo->prepare(
                        'UPDATE password_reset_tokens SET used_at = NOW()
                         WHERE token_hash = :token_hash AND used_at IS NULL'
                    )->execute(['token_hash' => hash('sha256', $token)]);
                    audit('auth.password_reset_email_failed', (int) $accountId);
                    error_log('Password reset email could not be sent for user ID ' . (int) $accountId . '. Check the configured mail transport.');
                }
            }
            $confirmation = true;
        }

        if ($confirmation) {
            $content = '<section class="card narrow"><p>If an active account matches that address, password reset instructions have been sent. If no message arrives, contact the system administrator to check email delivery.</p>'
                . '<p><a class="button secondary" href="' . e(url('login')) . '">Return to sign in</a></p></section>';
        } elseif (!$config['password_reset_enabled']) {
            $content = '<section class="card narrow"><p>Password reset is not configured yet. Contact the system administrator to configure <code>APP_URL</code> and <code>MAIL_FROM</code> in the root <code>.env</code> file and set up the server mail transport.</p>'
                . '<p><a class="button secondary" href="' . e(url('login')) . '">Return to sign in</a></p></section>';
        } else {
            $content = '<section class="card narrow"><p>Enter your account email address. If an active account matches, we will send a time-limited reset link.</p>'
                . '<form method="post" action="' . e(url('forgot_password')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
                . '<label>Email address<input type="email" name="email" maxlength="190" required autocomplete="email"></label>'
                . '<button type="submit">Send reset link</button></form>'
                . '<p><a href="' . e(url('login')) . '">Return to sign in</a></p></section>';
        }
        render_page('Reset password', $content, null, $message);
        exit;
    }

    if ($page === 'reset_password') {
        $token = (string) ($_GET['token'] ?? $_POST['token'] ?? '');
        if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
            http_response_code(400);
            throw new RuntimeException('This password reset link is invalid or has expired. Request a new link.');
        }
        $tokenHash = hash('sha256', $token);
        if ($method === 'POST') {
            verify_csrf();
            $password = (string) ($_POST['password'] ?? '');
            $confirmation = (string) ($_POST['password_confirmation'] ?? '');
            if (strlen($password) < 12 || $password !== $confirmation) {
                throw new RuntimeException('Use a password of at least 12 characters and ensure both password fields match.');
            }

            $pdo = db();
            $pdo->beginTransaction();
            try {
                $tokenQuery = $pdo->prepare(
                    'SELECT t.id, t.user_id FROM password_reset_tokens t
                     INNER JOIN users u ON u.id = t.user_id
                     WHERE t.token_hash = :token_hash AND t.used_at IS NULL
                       AND t.expires_at > NOW() AND u.is_active = 1
                     FOR UPDATE'
                );
                $tokenQuery->execute(['token_hash' => $tokenHash]);
                $reset = $tokenQuery->fetch();
                if (!$reset) {
                    throw new RuntimeException('This password reset link is invalid or has expired. Request a new link.');
                }
                $pdo->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :user_id')
                    ->execute([
                        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                        'user_id' => (int) $reset['user_id'],
                    ]);
                $pdo->prepare(
                    'UPDATE password_reset_tokens SET used_at = NOW()
                     WHERE user_id = :user_id AND used_at IS NULL'
                )->execute(['user_id' => (int) $reset['user_id']]);
                audit('auth.password_reset_completed', (int) $reset['user_id']);
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $exception;
            }
            $_SESSION['flash'] = 'Your password has been changed. Sign in with your new password.';
            redirect('login');
        }

        $tokenQuery = db()->prepare(
            'SELECT 1 FROM password_reset_tokens t
             INNER JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = :token_hash AND t.used_at IS NULL
               AND t.expires_at > NOW() AND u.is_active = 1 LIMIT 1'
        );
        $tokenQuery->execute(['token_hash' => $tokenHash]);
        if (!$tokenQuery->fetchColumn()) {
            http_response_code(400);
            throw new RuntimeException('This password reset link is invalid or has expired. Request a new link.');
        }
        $content = '<section class="card narrow"><p>Choose a new password of at least 12 characters. This link expires after one hour and can only be used once.</p>'
            . '<form method="post" action="' . e(url('reset_password')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
            . '<input type="hidden" name="token" value="' . e($token) . '">'
            . '<label>New password<input type="password" name="password" minlength="12" required autocomplete="new-password"></label>'
            . '<label>Confirm new password<input type="password" name="password_confirmation" minlength="12" required autocomplete="new-password"></label>'
            . '<button type="submit">Change password</button></form></section>';
        render_page('Choose a new password', $content, null, $message);
        exit;
    }

    if (!$user && $page !== 'login') {
        redirect(is_first_setup_required() ? 'setup' : 'login');
    }

    if ($page === 'login') {
        if ($user) {
            redirect('dashboard');
        }
        if (is_first_setup_required()) {
            redirect('setup');
        }
        if ($method === 'POST') {
            verify_csrf();
            $ipHash = hash('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            $prune = db()->prepare('DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 1 DAY)');
            $prune->execute();
            $attempts = db()->prepare(
                'SELECT COUNT(*) FROM login_attempts
                 WHERE ip_hash = :ip_hash AND attempted_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
            );
            $attempts->execute(['ip_hash' => $ipHash]);
            if ((int) $attempts->fetchColumn() >= 5) {
                throw new RuntimeException('Too many unsuccessful sign-in attempts. Wait 15 minutes and try again.');
            }

            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            $password = (string) ($_POST['password'] ?? '');
            $statement = db()->prepare(
                'SELECT u.id, u.password_hash, u.is_active, u.full_name
                 FROM users u WHERE u.email = :email LIMIT 1'
            );
            $statement->execute(['email' => $email]);
            $account = $statement->fetch();

            if (!$account || !(bool) $account['is_active'] || !password_verify($password, $account['password_hash'])) {
                $recordAttempt = db()->prepare('INSERT INTO login_attempts (ip_hash) VALUES (:ip_hash)');
                $recordAttempt->execute(['ip_hash' => $ipHash]);
                audit('auth.login_failed', isset($account['id']) ? (int) $account['id'] : null, ['email' => $email]);
                throw new RuntimeException('Email or password is incorrect, or the account is inactive.');
            }

            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $account['id'];
            $_SESSION['last_activity'] = time();
            db()->prepare('DELETE FROM login_attempts WHERE ip_hash = :ip_hash')->execute(['ip_hash' => $ipHash]);
            audit('auth.login');
            redirect('dashboard');
        }
        $notice = (string) ($_GET['notice'] ?? '');
        $content = '<section class="card narrow"><form method="post" action="' . e(url('login')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
            . '<label>Email address<input type="email" name="email" maxlength="190" required autocomplete="username"></label>'
            . '<label>Password<input type="password" name="password" required autocomplete="current-password"></label>'
            . '<button type="submit">Sign in</button></form><p><a href="' . e(url('forgot_password')) . '">Forgot your password?</a></p></section>';
        render_page('Sign in', $content, null, $message !== '' ? $message : $notice);
        exit;
    }

    $user = require_login();

    if ($page === 'dashboard') {
        $scope = has_permission($user, 'projects.view_all') ? '' : ' WHERE project_manager_id = :user_id';
        $countStatement = db()->prepare(
            'SELECT status, COUNT(*) AS total FROM projects' . $scope . ' GROUP BY status'
        );
        if (!has_permission($user, 'projects.view_all')) {
            $countStatement->execute(['user_id' => (int) $user['id']]);
        } else {
            $countStatement->execute();
        }
        $statusCounts = ['planned' => 0, 'active' => 0, 'closed' => 0];
        foreach ($countStatement->fetchAll() as $statusRow) {
            if (array_key_exists($statusRow['status'], $statusCounts)) {
                $statusCounts[$statusRow['status']] = (int) $statusRow['total'];
            }
        }
        $projectCount = array_sum($statusCounts);
        $financialSummary = null;
        if (has_permission($user, 'finance.view')) {
            $financialSummary = db()->query(
                'SELECT
                    (SELECT COALESCE(SUM(approved_amount), 0) FROM project_budgets) AS approved_budget,
                    (SELECT COALESCE(SUM(amount), 0) FROM project_expenditures) AS actual_expenditure'
            )->fetch();
        }
        $pendingReports = 0;
        $reportMetricLabel = 'Your progress reports';
        $reportMetricHint = 'Reports submitted';
        if (has_permission($user, 'progress_reports.view_all')) {
            $pendingReports = (int) db()->query(
                "SELECT COUNT(*) FROM project_progress_reports WHERE review_status = 'submitted'"
            )->fetchColumn();
            $reportMetricLabel = 'Awaiting review';
            $reportMetricHint = 'Progress reports';
        } elseif (has_permission($user, 'progress_reports.submit')) {
            $reportCount = db()->prepare(
                'SELECT COUNT(*) FROM project_progress_reports WHERE reported_by = :user_id'
            );
            $reportCount->execute(['user_id' => (int) $user['id']]);
            $pendingReports = (int) $reportCount->fetchColumn();
        }
        $recentQuery = db()->prepare(
            'SELECT p.id, p.project_code, p.title, p.status, p.updated_at,
                    manager.full_name AS manager_name,
                    (SELECT pr.percent_complete FROM project_progress_reports pr
                     WHERE pr.project_id = p.id
                     ORDER BY pr.reporting_date DESC, pr.created_at DESC LIMIT 1) AS latest_progress
             FROM projects p
             INNER JOIN users manager ON manager.id = p.project_manager_id'
             . (has_permission($user, 'projects.view_all') ? '' : ' WHERE p.project_manager_id = :user_id')
             . ' ORDER BY p.updated_at DESC LIMIT 5'
        );
        if (!has_permission($user, 'projects.view_all')) {
            $recentQuery->execute(['user_id' => (int) $user['id']]);
        } else {
            $recentQuery->execute();
        }
        $recentRows = '';
        foreach ($recentQuery->fetchAll() as $recentProject) {
            $progress = $recentProject['latest_progress'] !== null ? (float) $recentProject['latest_progress'] : null;
            $progressLabel = $progress === null ? 'No update' : number_format($progress, 0) . '%';
            $progressBar = $progress === null ? '' : '<div class="progress-track"><div class="progress-fill" style="width:' . e((string) $progress) . '%"></div></div>';
            $recentRows .= '<div class="recent-project"><div><a class="recent-project-title" href="' . e(url('project', ['id' => (int) $recentProject['id']])) . '">' . e($recentProject['title']) . '</a>'
                . '<div class="recent-project-meta">' . e($recentProject['project_code']) . ' · ' . e($recentProject['manager_name']) . '</div></div>'
                . '<div class="recent-project-progress">' . $progressBar . '<span>' . e($progressLabel) . '</span></div></div>';
        }
        if ($recentRows === '') {
            $recentRows = '<div class="empty-state">No projects to show yet. Create or assign a project to get started.</div>';
        }
        $statusBarRows = '';
        foreach (['planned' => 'Planned', 'active' => 'In progress', 'closed' => 'Closed'] as $statusKey => $statusLabel) {
            $count = $statusCounts[$statusKey];
            $barWidth = $projectCount > 0 ? (int) round($count / $projectCount * 100) : 0;
            $statusBarRows .= '<div class="status-row"><span>' . e($statusLabel) . '</span><div class="status-track"><div class="status-fill ' . e($statusKey) . '" style="width:' . $barWidth . '%"></div></div><span class="status-count">' . $count . '</span></div>';
        }
        $greeting = (int) date('G') < 12 ? 'Good morning' : ((int) date('G') < 17 ? 'Good afternoon' : 'Good evening');
        $reviewLink = has_permission($user, 'progress_reports.view_all')
            ? '<a class="button secondary" href="' . e(url('progress_reports')) . '">Review reports</a>'
            : (has_permission($user, 'progress_reports.submit') ? '<a class="button secondary" href="' . e(url('progress_reports')) . '">My reports</a>' : '');
        $content = '<section class="welcome"><div class="welcome-copy"><h2>' . e($greeting) . ', ' . e($user['full_name']) . '</h2><p>Here is the latest overview of your municipal projects.</p></div>'
            . '<div class="welcome-actions">' . $reviewLink
            . (has_permission($user, 'projects.create') ? '<a class="button" href="' . e(url('project_new')) . '">Create project</a>' : '') . '</div></section>'
            . '<section class="dashboard-grid">'
            . '<article class="metric-card"><div class="metric-top"><span class="metric-label">Total projects</span><span class="metric-icon">P</span></div><strong class="metric-value">' . $projectCount . '</strong><span class="metric-footnote">Projects in your access scope</span></article>'
            . '<article class="metric-card"><div class="metric-top"><span class="metric-label">In progress</span><span class="metric-icon">IP</span></div><strong class="metric-value">' . $statusCounts['active'] . '</strong><span class="metric-footnote">Marked active in the register</span></article>'
            . '<article class="metric-card"><div class="metric-top"><span class="metric-label">' . e($reportMetricLabel) . '</span><span class="metric-icon">R</span></div><strong class="metric-value">' . $pendingReports . '</strong><span class="metric-footnote">' . e($reportMetricHint) . '</span></article>'
            . '<article class="metric-card"><div class="metric-top"><span class="metric-label">Closed projects</span><span class="metric-icon">C</span></div><strong class="metric-value">' . $statusCounts['closed'] . '</strong><span class="metric-footnote">Status recorded as closed</span></article>'
            . ($financialSummary !== null
                ? '<article class="metric-card"><div class="metric-top"><span class="metric-label">Approved budgets (KES)</span><span class="metric-icon">B</span></div><strong class="metric-value">' . e(number_format((float) $financialSummary['approved_budget'], 2)) . '</strong><span class="metric-footnote">Recorded across projects</span></article>'
                    . '<article class="metric-card"><div class="metric-top"><span class="metric-label">Actual expenditure (KES)</span><span class="metric-icon">E</span></div><strong class="metric-value">' . e(number_format((float) $financialSummary['actual_expenditure'], 2)) . '</strong><span class="metric-footnote">Recorded across projects</span></article>'
                : '')
            . '</section>'
            . '<section class="dashboard-columns"><article class="card"><div class="section-header"><h2>Project portfolio</h2><a class="text-link" href="' . e(url('projects')) . '">View all projects</a></div>'
            . '<div class="status-breakdown">' . $statusBarRows . '</div></article>'
            . '<article class="card"><div class="section-header"><h2>Recently updated</h2><a class="text-link" href="' . e(url('projects')) . '">Project register</a></div>'
            . '<div class="recent-project-list">' . $recentRows . '</div></article></section>'
            . '<p class="dashboard-note">Planned deadlines and inspection schedules are not yet tracked in this system.</p>';
        render_page('Dashboard', $content, $user, $message);
        exit;
    }

    if ($page === 'document_upload') {
        require_permission($user, 'documents.upload');
        if ($method !== 'POST') {
            http_response_code(405);
            throw new RuntimeException('Use the project evidence form to upload a document.');
        }
        verify_csrf();
        $projectId = filter_var($_POST['project_id'] ?? null, FILTER_VALIDATE_INT);
        if (!$projectId) {
            throw new RuntimeException('Select a valid project.');
        }
        $projectQuery = db()->prepare(
            'SELECT id FROM projects WHERE id = :project_id'
            . (has_permission($user, 'projects.view_all') ? '' : ' AND project_manager_id = :user_id')
        );
        $projectParameters = ['project_id' => (int) $projectId];
        if (!has_permission($user, 'projects.view_all')) {
            $projectParameters['user_id'] = (int) $user['id'];
        }
        $projectQuery->execute($projectParameters);
        if (!$projectQuery->fetchColumn()) {
            http_response_code(404);
            throw new RuntimeException('Project not found or not assigned to your account.');
        }

        $upload = $_FILES['document'] ?? null;
        if (!is_array($upload) || !isset($upload['error'], $upload['tmp_name'], $upload['name'])) {
            throw new RuntimeException('Choose a document to upload.');
        }
        if ((int) $upload['error'] !== UPLOAD_ERR_OK) {
            $uploadErrors = [
                UPLOAD_ERR_INI_SIZE => 'The document exceeds the server upload limit.',
                UPLOAD_ERR_FORM_SIZE => 'The document exceeds the 50 MB upload limit.',
                UPLOAD_ERR_PARTIAL => 'The document upload was incomplete. Try again.',
                UPLOAD_ERR_NO_FILE => 'Choose a document to upload.',
                UPLOAD_ERR_NO_TMP_DIR => 'The server upload temporary directory is unavailable.',
                UPLOAD_ERR_CANT_WRITE => 'The server could not store the uploaded document.',
                UPLOAD_ERR_EXTENSION => 'A server extension prevented the document upload.',
            ];
            throw new RuntimeException($uploadErrors[(int) $upload['error']] ?? 'The document upload failed.');
        }
        if (!is_uploaded_file((string) $upload['tmp_name'])) {
            throw new RuntimeException('The uploaded document could not be verified.');
        }
        $fileSize = filesize((string) $upload['tmp_name']);
        $maxBytes = 50 * 1024 * 1024;
        if ($fileSize === false || $fileSize < 1 || $fileSize > $maxBytes) {
            throw new RuntimeException('Choose a file smaller than or equal to 50 MB.');
        }
        if (!class_exists('finfo')) {
            throw new RuntimeException('File type validation is unavailable. Enable the PHP Fileinfo extension.');
        }
        $fileInfo = new finfo(FILEINFO_MIME_TYPE);
        $mediaType = $fileInfo->file((string) $upload['tmp_name']);
        $allowedTypes = [
            'application/pdf' => ['pdf'],
            'image/jpeg' => ['jpg', 'jpeg'],
            'image/png' => ['png'],
            'video/mp4' => ['mp4'],
            'video/webm' => ['webm'],
        ];
        $originalName = basename(str_replace('\\', '/', (string) $upload['name']));
        $originalName = preg_replace('/[\x00-\x1F\x7F]/u', '', $originalName) ?? '';
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if (!is_string($mediaType) || !isset($allowedTypes[$mediaType]) || !in_array($extension, $allowedTypes[$mediaType], true)) {
            throw new RuntimeException('Only matching PDF, JPEG, PNG, MP4, and WEBM evidence files are accepted.');
        }
        if ($originalName === '' || strlen($originalName) > 255) {
            throw new RuntimeException('The document filename is empty or too long.');
        }
        $description = trim((string) ($_POST['description'] ?? ''));
        if (strlen($description) > 500) {
            throw new RuntimeException('Keep the evidence description under 500 characters.');
        }

        $privateRoot = private_storage_path();
        if (!is_dir($privateRoot) && !mkdir($privateRoot, 0700, true) && !is_dir($privateRoot)) {
            throw new RuntimeException('Private evidence storage could not be created.');
        }
        $privateRoot = private_storage_path();
        $storageName = bin2hex(random_bytes(16)) . '.' . $allowedTypes[$mediaType][0];
        $storedPath = $privateRoot . DIRECTORY_SEPARATOR . $storageName;
        if (!move_uploaded_file((string) $upload['tmp_name'], $storedPath)) {
            throw new RuntimeException('The server could not move the document into private storage.');
        }
        $fileHash = hash_file('sha256', $storedPath);
        if (!is_string($fileHash)) {
            unlink($storedPath);
            throw new RuntimeException('The server could not verify the stored document.');
        }
        $pdo = db();
        try {
            $pdo->beginTransaction();
            $insert = $pdo->prepare(
                'INSERT INTO project_documents
                    (project_id, original_name, storage_name, media_type, size_bytes, sha256, description, uploaded_by)
                 VALUES
                    (:project_id, :original_name, :storage_name, :media_type, :size_bytes, :sha256, :description, :uploaded_by)'
            );
            $insert->execute([
                'project_id' => (int) $projectId,
                'original_name' => $originalName,
                'storage_name' => $storageName,
                'media_type' => $mediaType,
                'size_bytes' => $fileSize,
                'sha256' => $fileHash,
                'description' => $description !== '' ? $description : null,
                'uploaded_by' => (int) $user['id'],
            ]);
            $documentId = (int) $pdo->lastInsertId();
            audit('documents.uploaded', $documentId, [
                'project_id' => (int) $projectId,
                'media_type' => $mediaType,
                'size_bytes' => $fileSize,
            ]);
            $pdo->commit();
        } catch (Throwable $exception) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if (is_file($storedPath)) {
                if (!unlink($storedPath)) {
                    error_log('Unable to remove an uploaded evidence file after its database record failed.');
                }
            }
            throw $exception;
        }
        $_SESSION['flash'] = 'Private project evidence uploaded.';
        redirect('project', ['id' => (int) $projectId]);
    }

    if ($page === 'document_download') {
        require_permission($user, 'documents.view');
        $documentId = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT);
        if (!$documentId) {
            http_response_code(404);
            throw new RuntimeException('Evidence document not found.');
        }
        $documentQuery = db()->prepare(
            'SELECT d.*, p.project_manager_id
             FROM project_documents d
             INNER JOIN projects p ON p.id = d.project_id
             WHERE d.id = :document_id'
             . (has_permission($user, 'projects.view_all') ? '' : ' AND p.project_manager_id = :user_id')
        );
        $documentParameters = ['document_id' => (int) $documentId];
        if (!has_permission($user, 'projects.view_all')) {
            $documentParameters['user_id'] = (int) $user['id'];
        }
        $documentQuery->execute($documentParameters);
        $document = $documentQuery->fetch();
        if (!$document) {
            http_response_code(404);
            throw new RuntimeException('Evidence document not found or not assigned to your account.');
        }
        if (!preg_match('/^[a-f0-9]{32}\.(pdf|jpg|jpeg|png|mp4|webm)$/', (string) $document['storage_name'])) {
            http_response_code(500);
            throw new RuntimeException('The stored evidence document has an invalid storage reference. Contact the administrator.');
        }
        $privateRoot = private_storage_path();
        $resolvedRoot = realpath($privateRoot);
        $resolvedFile = realpath($privateRoot . DIRECTORY_SEPARATOR . $document['storage_name']);
        $allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'video/mp4', 'video/webm'];
        if (
            $resolvedRoot === false
            || $resolvedFile === false
            || !str_starts_with(
                DIRECTORY_SEPARATOR === '\\' ? strtolower($resolvedFile) : $resolvedFile,
                (DIRECTORY_SEPARATOR === '\\' ? strtolower(rtrim($resolvedRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) : rtrim($resolvedRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
            )
            || !in_array($document['media_type'], $allowedTypes, true)
        ) {
            http_response_code(404);
            throw new RuntimeException('The private evidence file is unavailable.');
        }
        $fileContents = file_get_contents($resolvedFile);
        $fileHash = hash_file('sha256', $resolvedFile);
        if (
            !is_string($fileContents)
            || strlen($fileContents) !== (int) $document['size_bytes']
            || !is_string($fileHash)
            || !hash_equals((string) $document['sha256'], $fileHash)
        ) {
            http_response_code(500);
            throw new RuntimeException('The stored evidence document failed its integrity check. Contact the administrator.');
        }
        audit('documents.downloaded', (int) $document['id'], ['project_id' => (int) $document['project_id']]);
        $extension = pathinfo((string) $document['storage_name'], PATHINFO_EXTENSION);
        header('Content-Type: ' . $document['media_type']);
        header('Content-Length: ' . strlen($fileContents));
        header('Content-Disposition: inline; filename="project-evidence.' . $extension . '"; filename*=UTF-8\'\'' . rawurlencode((string) $document['original_name']));
        echo $fileContents;
        exit;
    }

    $exportPages = [
        'projects_export' => 'projects.view',
        'progress_export' => 'progress_reports.view_all',
        'budgets_export' => 'finance.view',
        'expenditure_export' => 'finance.view',
        'procurement_export' => 'procurement.view',
    ];
    if (isset($exportPages[$page])) {
        $exportPermission = $exportPages[$page];
        if ($page === 'progress_export' && !has_permission($user, 'progress_reports.view_all') && has_permission($user, 'progress_reports.submit')) {
            $exportPermission = 'progress_reports.submit';
        }
        require_permission($user, $exportPermission);

        $exports = [
            'projects_export' => [
                'filename' => 'municipal-projects',
                'columns' => [
                    'Project code' => 'project_code',
                    'Project title' => 'title',
                    'Department' => 'department',
                    'Location' => 'location',
                    'Status' => 'status',
                    'Project manager' => 'manager_name',
                    'Latest reported completion (%)' => 'latest_progress',
                ],
                'sql' => 'SELECT p.project_code, p.title, p.department, p.location, p.status, u.full_name AS manager_name,
                                 (SELECT pr.percent_complete FROM project_progress_reports pr
                                  WHERE pr.project_id = p.id
                                  ORDER BY pr.reporting_date DESC, pr.created_at DESC LIMIT 1) AS latest_progress
                          FROM projects p INNER JOIN users u ON u.id = p.project_manager_id',
                'scope' => 'p.project_manager_id',
            ],
            'progress_export' => [
                'filename' => 'municipal-progress-reports',
                'columns' => [
                    'Project code' => 'project_code',
                    'Project title' => 'project_title',
                    'Reporting date' => 'reporting_date',
                    'Reported completion (%)' => 'percent_complete',
                    'Work completed' => 'work_completed',
                    'Challenges' => 'challenges',
                    'Next steps' => 'next_steps',
                    'Review status' => 'review_status',
                    'Review note' => 'review_note',
                    'Reported by' => 'reporter_name',
                ],
                'sql' => 'SELECT p.project_code, p.title AS project_title, pr.reporting_date, pr.percent_complete,
                                 pr.work_completed, pr.challenges, pr.next_steps, pr.review_status, pr.review_note,
                                 reporter.full_name AS reporter_name
                          FROM project_progress_reports pr
                          INNER JOIN projects p ON p.id = pr.project_id
                          INNER JOIN users reporter ON reporter.id = pr.reported_by',
                'scope' => 'pr.reported_by',
            ],
            'budgets_export' => [
                'filename' => 'municipal-project-budgets-kes',
                'columns' => [
                    'Project code' => 'project_code',
                    'Project title' => 'project_title',
                    'Financial year' => 'financial_year',
                    'Funding source' => 'funding_source',
                    'Approved budget (KES)' => 'approved_amount',
                    'Recorded expenditure (KES)' => 'recorded_expenditure',
                    'Remaining budget (KES)' => 'remaining_budget',
                ],
                'sql' => 'SELECT p.project_code, p.title AS project_title, b.financial_year, b.funding_source,
                                 b.approved_amount, COALESCE(SUM(e.amount), 0) AS recorded_expenditure,
                                 b.approved_amount - COALESCE(SUM(e.amount), 0) AS remaining_budget
                          FROM project_budgets b
                          INNER JOIN projects p ON p.id = b.project_id
                          LEFT JOIN project_expenditures e ON e.budget_id = b.id
                          GROUP BY b.id, p.project_code, p.title, b.financial_year, b.funding_source, b.approved_amount',
                'scope' => null,
            ],
            'expenditure_export' => [
                'filename' => 'municipal-project-expenditure-kes',
                'columns' => [
                    'Project code' => 'project_code',
                    'Project title' => 'project_title',
                    'Date' => 'expenditure_date',
                    'Category' => 'category',
                    'Supplier' => 'supplier',
                    'Reference' => 'reference',
                    'Amount (KES)' => 'amount',
                    'Financial year' => 'financial_year',
                    'Description' => 'description',
                ],
                'sql' => 'SELECT p.project_code, p.title AS project_title, e.expenditure_date, e.category, e.supplier,
                                 e.reference, e.amount, b.financial_year, e.description
                          FROM project_expenditures e
                          INNER JOIN projects p ON p.id = e.project_id
                          LEFT JOIN project_budgets b ON b.id = e.budget_id',
                'scope' => null,
            ],
            'procurement_export' => [
                'filename' => 'municipal-procurement-register',
                'columns' => [
                    'Project code' => 'project_code',
                    'Project title' => 'project_title',
                    'Procurement title' => 'procurement_title',
                    'Method' => 'procurement_method',
                    'Stage' => 'stage',
                    'Supplier' => 'supplier',
                    'Tender/contract reference' => 'reference',
                    'Estimated amount (KES)' => 'estimated_amount',
                    'Contract amount (KES)' => 'contract_amount',
                    'Planned date' => 'planned_date',
                    'Award date' => 'award_date',
                    'Notes' => 'notes',
                ],
                'sql' => 'SELECT p.project_code, p.title AS project_title, r.title AS procurement_title,
                                 r.procurement_method, r.stage, r.supplier, r.reference, r.estimated_amount,
                                 r.contract_amount, r.planned_date, r.award_date, r.notes
                          FROM procurement_records r INNER JOIN projects p ON p.id = r.project_id',
                'scope' => null,
            ],
        ];
        $export = $exports[$page];
        $sql = $export['sql'];
        $parameters = [];
        if ($export['scope'] !== null) {
            $scope = $export['scope'];
            if ($page === 'projects_export' && !has_permission($user, 'projects.view_all')) {
                $sql .= ' WHERE ' . $scope . ' = :user_id';
                $parameters['user_id'] = (int) $user['id'];
            } elseif ($page === 'progress_export' && !has_permission($user, 'progress_reports.view_all')) {
                $sql .= ' WHERE ' . $scope . ' = :user_id';
                $parameters['user_id'] = (int) $user['id'];
            }
        }
        $statement = db()->prepare($sql . ' ORDER BY 1');
        $statement->execute($parameters);
        audit('exports.csv_requested', null, ['export_type' => $page]);
        $output = fopen('php://output', 'wb');
        if ($output === false) {
            throw new RuntimeException('The CSV export could not be opened.');
        }
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $export['filename'] . '-' . date('Y-m-d') . '.csv"');
        echo "\xEF\xBB\xBF";
        $headers = array_keys($export['columns']);
        if (fputcsv($output, $headers, ',', '"', '') === false) {
            fclose($output);
            throw new RuntimeException('The CSV export header could not be written.');
        }
        while (($exportRow = $statement->fetch(PDO::FETCH_ASSOC)) !== false) {
            $values = [];
            foreach ($export['columns'] as $field) {
                $value = $exportRow[$field] ?? '';
                $value = $value === null ? '' : (string) $value;
                if (preg_match('/^[\x00-\x20]*[=+\-@]/', $value) === 1) {
                    $value = "'" . $value;
                }
                $values[] = $value;
            }
            if (fputcsv($output, $values, ',', '"', '') === false) {
                fclose($output);
                throw new RuntimeException('The CSV export could not be written completely.');
            }
        }
        fclose($output);
        exit;
    }

    if ($page === 'finance') {
        require_permission($user, 'finance.view');

        $dateValue = static function (string $value): ?string {
            $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
            return $date && $date->format('Y-m-d') === $value ? $value : null;
        };
        $amountIsValid = static function (string $value, bool $allowZero = false): bool {
            if (!preg_match('/^\d{1,13}(?:\.\d{1,2})?$/', $value)) {
                return false;
            }
            return $allowZero || (float) $value > 0;
        };

        if ($method === 'POST') {
            require_permission($user, 'finance.manage');
            verify_csrf();
            $action = (string) ($_POST['action'] ?? '');
            $projectId = filter_var($_POST['project_id'] ?? null, FILTER_VALIDATE_INT);
            if (!$projectId) {
                throw new RuntimeException('Select a valid project.');
            }
            $projectCheck = db()->prepare('SELECT id FROM projects WHERE id = :id');
            $projectCheck->execute(['id' => (int) $projectId]);
            if (!$projectCheck->fetchColumn()) {
                throw new RuntimeException('Select a valid project.');
            }

            if ($action === 'add_budget') {
                $year = trim((string) ($_POST['financial_year'] ?? ''));
                $fundingSource = trim((string) ($_POST['funding_source'] ?? ''));
                $amount = trim((string) ($_POST['approved_amount'] ?? ''));
                if (!preg_match('/^\d{4}$/', $year) || (int) $year < 2000 || (int) $year > 2100) {
                    throw new RuntimeException('Enter a financial year between 2000 and 2100.');
                }
                if ($fundingSource === '' || strlen($fundingSource) > 180 || !$amountIsValid($amount)) {
                    throw new RuntimeException('Enter a funding source and a positive approved amount with no more than two decimal places.');
                }
                $pdo = db();
                $pdo->beginTransaction();
                try {
                    $duplicate = $pdo->prepare(
                        'SELECT id FROM project_budgets
                         WHERE project_id = :project_id AND financial_year = :financial_year AND funding_source = :funding_source
                         FOR UPDATE'
                    );
                    $duplicate->execute([
                        'project_id' => (int) $projectId,
                        'financial_year' => (int) $year,
                        'funding_source' => $fundingSource,
                    ]);
                    if ($duplicate->fetchColumn()) {
                        throw new RuntimeException('A budget for this project, financial year, and funding source already exists.');
                    }
                    $insert = $pdo->prepare(
                        'INSERT INTO project_budgets (project_id, financial_year, funding_source, approved_amount, recorded_by)
                         VALUES (:project_id, :financial_year, :funding_source, :approved_amount, :recorded_by)'
                    );
                    $insert->execute([
                        'project_id' => (int) $projectId,
                        'financial_year' => (int) $year,
                        'funding_source' => $fundingSource,
                        'approved_amount' => $amount,
                        'recorded_by' => (int) $user['id'],
                    ]);
                    $budgetId = (int) $pdo->lastInsertId();
                    audit('finance.budget_recorded', $budgetId, [
                        'project_id' => (int) $projectId,
                        'financial_year' => (int) $year,
                        'funding_source' => $fundingSource,
                        'approved_amount' => $amount,
                    ]);
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }
                $_SESSION['flash'] = 'Project budget recorded.';
                redirect('finance');
            }

            if ($action === 'update_budget') {
                $budgetId = filter_var($_POST['budget_id'] ?? null, FILTER_VALIDATE_INT);
                $amount = trim((string) ($_POST['approved_amount'] ?? ''));
                if (!$budgetId || !$amountIsValid($amount)) {
                    throw new RuntimeException('Select a valid budget and enter a positive approved amount.');
                }
                $amount = number_format((float) $amount, 2, '.', '');
                $pdo = db();
                $pdo->beginTransaction();
                try {
                    $budgetQuery = $pdo->prepare(
                        'SELECT approved_amount FROM project_budgets
                         WHERE id = :budget_id AND project_id = :project_id FOR UPDATE'
                    );
                    $budgetQuery->execute(['budget_id' => (int) $budgetId, 'project_id' => (int) $projectId]);
                    $previousAmount = $budgetQuery->fetchColumn();
                    if ($previousAmount === false) {
                        throw new RuntimeException('The selected budget does not belong to this project.');
                    }
                    if ((string) $previousAmount !== $amount) {
                        $update = $pdo->prepare(
                            'UPDATE project_budgets SET approved_amount = :amount WHERE id = :budget_id'
                        );
                        $update->execute(['amount' => $amount, 'budget_id' => (int) $budgetId]);
                        audit('finance.budget_amount_updated', (int) $budgetId, [
                            'project_id' => (int) $projectId,
                            'from' => (string) $previousAmount,
                            'to' => $amount,
                        ]);
                    }
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }
                $_SESSION['flash'] = 'Project budget amount updated and audited.';
                redirect('finance');
            }

            if ($action === 'add_expenditure') {
                $date = trim((string) ($_POST['expenditure_date'] ?? ''));
                $amount = trim((string) ($_POST['amount'] ?? ''));
                $category = trim((string) ($_POST['category'] ?? ''));
                $supplier = trim((string) ($_POST['supplier'] ?? ''));
                $reference = trim((string) ($_POST['reference'] ?? ''));
                $description = trim((string) ($_POST['description'] ?? ''));
                $budgetInput = trim((string) ($_POST['budget_id'] ?? ''));
                $parsedDate = $dateValue($date);
                $budgetId = $budgetInput === '' ? null : filter_var($budgetInput, FILTER_VALIDATE_INT);
                if (!$parsedDate || !$amountIsValid($amount)) {
                    throw new RuntimeException('Enter a valid expenditure date and a positive amount with no more than two decimal places.');
                }
                if ($category === '' || strlen($category) > 100 || strlen($supplier) > 180 || strlen($reference) > 120 || strlen($description) > 20000) {
                    throw new RuntimeException('Enter a category and keep the expenditure fields within their stated length limits.');
                }
                if ($budgetInput !== '' && !$budgetId) {
                    throw new RuntimeException('Select a valid project budget, or leave it unassigned.');
                }
                $pdo = db();
                $pdo->beginTransaction();
                try {
                    if ($budgetId) {
                        $budgetCheck = $pdo->prepare(
                            'SELECT id FROM project_budgets WHERE id = :budget_id AND project_id = :project_id FOR UPDATE'
                        );
                        $budgetCheck->execute(['budget_id' => (int) $budgetId, 'project_id' => (int) $projectId]);
                        if (!$budgetCheck->fetchColumn()) {
                            throw new RuntimeException('The selected budget does not belong to this project.');
                        }
                    }
                    $insert = $pdo->prepare(
                        'INSERT INTO project_expenditures
                            (project_id, budget_id, expenditure_date, amount, category, supplier, reference, description, recorded_by)
                         VALUES
                            (:project_id, :budget_id, :expenditure_date, :amount, :category, :supplier, :reference, :description, :recorded_by)'
                    );
                    $insert->execute([
                        'project_id' => (int) $projectId,
                        'budget_id' => $budgetId ? (int) $budgetId : null,
                        'expenditure_date' => $parsedDate,
                        'amount' => $amount,
                        'category' => $category,
                        'supplier' => $supplier !== '' ? $supplier : null,
                        'reference' => $reference !== '' ? $reference : null,
                        'description' => $description !== '' ? $description : null,
                        'recorded_by' => (int) $user['id'],
                    ]);
                    $expenditureId = (int) $pdo->lastInsertId();
                    audit('finance.expenditure_recorded', $expenditureId, [
                        'project_id' => (int) $projectId,
                        'amount' => $amount,
                        'category' => $category,
                        'reference' => $reference,
                    ]);
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }
                $_SESSION['flash'] = 'Project expenditure recorded.';
                redirect('finance');
            }

            throw new RuntimeException('Unknown finance action.');
        }

        $projects = db()->query('SELECT id, project_code, title FROM projects ORDER BY title, id')->fetchAll();
        $projectOptions = '<option value="">Select a project</option>';
        foreach ($projects as $financeProject) {
            $projectOptions .= '<option value="' . (int) $financeProject['id'] . '">' . e($financeProject['project_code'] . ' · ' . $financeProject['title']) . '</option>';
        }
        $budgetOptions = '<option value="">Not linked to a specific budget</option>';
        $budgetRows = db()->query(
            'SELECT b.id, b.project_id, b.financial_year, b.funding_source, b.approved_amount,
                    p.project_code, p.title,
                    COALESCE(SUM(e.amount), 0) AS spent
             FROM project_budgets b
             INNER JOIN projects p ON p.id = b.project_id
             LEFT JOIN project_expenditures e ON e.budget_id = b.id
             GROUP BY b.id, b.project_id, b.financial_year, b.funding_source, b.approved_amount, p.project_code, p.title
             ORDER BY b.financial_year DESC, p.title, b.funding_source'
        )->fetchAll();
        $budgetTableRows = '';
        $budgetActionHeader = has_permission($user, 'finance.manage') ? '<th>Update budget</th>' : '';
        foreach ($budgetRows as $budget) {
            $spent = (float) $budget['spent'];
            $approved = (float) $budget['approved_amount'];
            $remaining = $approved - $spent;
            $budgetOptions .= '<option value="' . (int) $budget['id'] . '">' . e($budget['project_code'] . ' · ' . $budget['financial_year'] . ' · ' . $budget['funding_source']) . '</option>';
            $budgetActionCell = has_permission($user, 'finance.manage')
                ? '<td><form class="assignment-form" method="post" action="' . e(url('finance')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="action" value="update_budget"><input type="hidden" name="project_id" value="' . (int) $budget['project_id'] . '"><input type="hidden" name="budget_id" value="' . (int) $budget['id'] . '"><label class="visually-hidden" for="budget-amount-' . (int) $budget['id'] . '">Approved amount in KES</label><input id="budget-amount-' . (int) $budget['id'] . '" type="number" name="approved_amount" min="0.01" step="0.01" required value="' . e(number_format($approved, 2, '.', '')) . '"><button class="small-button" type="submit">Save</button></form></td>'
                : '';
            $budgetTableRows .= '<tr><td>' . e($budget['project_code'] . ' · ' . $budget['title']) . '</td><td>' . e((string) $budget['financial_year']) . '</td><td>' . e($budget['funding_source']) . '</td><td>' . e(number_format($approved, 2)) . '</td><td>' . e(number_format($spent, 2)) . '</td><td>' . e(number_format($remaining, 2)) . '</td>' . $budgetActionCell . '</tr>';
        }
        if ($budgetTableRows === '') {
            $budgetTableRows = '<tr><td colspan="' . (has_permission($user, 'finance.manage') ? '7' : '6') . '">No project budgets have been recorded.</td></tr>';
        }
        $expenditureRows = '';
        $expenditureQuery = db()->query(
            'SELECT e.*, p.project_code, p.title, b.financial_year, recorder.full_name AS recorder_name
             FROM project_expenditures e
             INNER JOIN projects p ON p.id = e.project_id
             LEFT JOIN project_budgets b ON b.id = e.budget_id
             INNER JOIN users recorder ON recorder.id = e.recorded_by
             ORDER BY e.expenditure_date DESC, e.id DESC LIMIT 500'
        );
        foreach ($expenditureQuery->fetchAll() as $expenditure) {
            $expenditureRows .= '<tr><td>' . e($expenditure['expenditure_date']) . '</td><td>' . e($expenditure['project_code'] . ' · ' . $expenditure['title']) . '</td><td>' . e($expenditure['category']) . '</td><td>' . e($expenditure['supplier']) . '</td><td>' . e($expenditure['reference']) . '</td><td>' . e(number_format((float) $expenditure['amount'], 2)) . '</td><td>' . e($expenditure['financial_year'] === null ? 'Unassigned' : (string) $expenditure['financial_year']) . '</td></tr>';
        }
        if ($expenditureRows === '') {
            $expenditureRows = '<tr><td colspan="7">No project expenditure has been recorded.</td></tr>';
        }
        $budgetForm = has_permission($user, 'finance.manage')
            ? '<section class="card"><h2>Record approved budget</h2><form class="grid-form" method="post" action="' . e(url('finance')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="action" value="add_budget">'
                . '<label>Project<select name="project_id" required>' . $projectOptions . '</select></label><label>Financial year<input type="number" name="financial_year" min="2000" max="2100" value="' . e(date('Y')) . '" required></label>'
                . '<label>Funding source<input name="funding_source" maxlength="180" required></label><label>Approved amount (KES)<input type="number" name="approved_amount" min="0.01" step="0.01" required></label>'
                . '<div class="form-actions"><button type="submit">Save budget</button></div></form></section>'
            : '';
        $expenditureForm = has_permission($user, 'finance.manage')
            ? '<section class="card"><h2>Record expenditure</h2><form class="grid-form" method="post" action="' . e(url('finance')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="action" value="add_expenditure">'
                . '<label>Project<select name="project_id" required>' . $projectOptions . '</select></label><label>Related budget (optional)<select name="budget_id">' . $budgetOptions . '</select></label>'
                . '<label>Expenditure date<input type="date" name="expenditure_date" value="' . e(date('Y-m-d')) . '" required></label><label>Amount (KES)<input type="number" name="amount" min="0.01" step="0.01" required></label>'
                . '<label>Category<input name="category" maxlength="100" placeholder="e.g. Construction materials" required></label><label>Supplier<input name="supplier" maxlength="180"></label>'
                . '<label>Payment/reference number<input name="reference" maxlength="120"></label><label class="full-width">Description<textarea name="description" maxlength="20000" rows="3"></textarea></label>'
                . '<div class="form-actions"><button type="submit">Save expenditure</button></div></form></section>'
            : '';
        $content = '<section class="card"><p>Financial records are operational tracking entries. All amounts are KES; they do not represent county appropriation, payment authorization, or Municipal Board approval. Remaining budget is calculated only from expenditure linked to that budget.</p>'
            . '<p><a class="button secondary" href="' . e(url('budgets_export')) . '">Export budgets CSV</a> <a class="button secondary" href="' . e(url('expenditure_export')) . '">Export expenditure CSV</a></p></section>'
            . $budgetForm
            . '<section class="card"><h2>Project budgets (KES)</h2><div class="table-wrap"><table><thead><tr><th>Project</th><th>Financial year</th><th>Funding source</th><th>Approved</th><th>Recorded spent</th><th>Remaining</th>' . $budgetActionHeader . '</tr></thead><tbody>' . $budgetTableRows . '</tbody></table></div></section>'
            . $expenditureForm
            . '<section class="card"><h2>Recent expenditure (KES)</h2><div class="table-wrap"><table><thead><tr><th>Date</th><th>Project</th><th>Category</th><th>Supplier</th><th>Reference</th><th>Amount</th><th>Financial year</th></tr></thead><tbody>' . $expenditureRows . '</tbody></table></div></section>';
        render_page('Budgets & expenditure', $content, $user, $message);
        exit;
    }

    if ($page === 'procurement') {
        require_permission($user, 'procurement.view');
        if ($method === 'POST') {
            require_permission($user, 'procurement.manage');
            verify_csrf();
            $action = (string) ($_POST['action'] ?? '');
            $stages = ['planned', 'advertised', 'evaluation', 'award_pending', 'awarded', 'contract_active', 'completed', 'cancelled'];
            if ($action === 'update_stage') {
                $recordId = filter_var($_POST['record_id'] ?? null, FILTER_VALIDATE_INT);
                $newStage = (string) ($_POST['stage'] ?? '');
                if (!$recordId || !in_array($newStage, $stages, true)) {
                    throw new RuntimeException('Select a procurement record and a valid stage.');
                }
                $pdo = db();
                try {
                    $pdo->beginTransaction();
                    $recordQuery = $pdo->prepare(
                        'SELECT project_id, stage FROM procurement_records WHERE id = :id FOR UPDATE'
                    );
                    $recordQuery->execute(['id' => (int) $recordId]);
                    $record = $recordQuery->fetch();
                    if (!$record) {
                        throw new RuntimeException('The selected procurement record no longer exists.');
                    }
                    if ($record['stage'] !== $newStage) {
                        $update = $pdo->prepare('UPDATE procurement_records SET stage = :stage WHERE id = :id');
                        $update->execute(['stage' => $newStage, 'id' => (int) $recordId]);
                        audit('procurement.stage_updated', (int) $recordId, [
                            'project_id' => (int) $record['project_id'],
                            'from' => $record['stage'],
                            'to' => $newStage,
                        ]);
                    }
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }
                $_SESSION['flash'] = 'Procurement stage updated and audited.';
                redirect('procurement');
            }
            if ($action !== 'add_procurement') {
                throw new RuntimeException('Unknown procurement action.');
            }
            $projectId = filter_var($_POST['project_id'] ?? null, FILTER_VALIDATE_INT);
            $title = trim((string) ($_POST['title'] ?? ''));
            $methodValue = (string) ($_POST['procurement_method'] ?? '');
            $stage = (string) ($_POST['stage'] ?? '');
            $supplier = trim((string) ($_POST['supplier'] ?? ''));
            $reference = trim((string) ($_POST['reference'] ?? ''));
            $estimatedAmount = trim((string) ($_POST['estimated_amount'] ?? ''));
            $contractAmount = trim((string) ($_POST['contract_amount'] ?? ''));
            $plannedDate = trim((string) ($_POST['planned_date'] ?? ''));
            $awardDate = trim((string) ($_POST['award_date'] ?? ''));
            $notes = trim((string) ($_POST['notes'] ?? ''));
            $methods = ['open_tender', 'request_for_quotations', 'direct_procurement', 'framework', 'other'];
            $amountPattern = '/^\d{1,13}(?:\.\d{1,2})?$/';
            $parseDate = static function (string $value): ?string {
                $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
                return $date && $date->format('Y-m-d') === $value ? $value : null;
            };
            if (!$projectId || $title === '' || strlen($title) > 180 || !in_array($methodValue, $methods, true) || !in_array($stage, $stages, true)) {
                throw new RuntimeException('Enter a valid project, procurement title, method, and stage.');
            }
            if (strlen($supplier) > 180 || strlen($reference) > 120 || strlen($notes) > 20000) {
                throw new RuntimeException('One or more procurement fields exceed the allowed length.');
            }
            foreach (['estimated amount' => $estimatedAmount, 'contract amount' => $contractAmount] as $label => $amount) {
                if ($amount !== '' && !preg_match($amountPattern, $amount)) {
                    throw new RuntimeException('Enter a valid ' . $label . ' with no more than two decimal places.');
                }
            }
            $parsedPlannedDate = $plannedDate === '' ? null : $parseDate($plannedDate);
            $parsedAwardDate = $awardDate === '' ? null : $parseDate($awardDate);
            if (($plannedDate !== '' && $parsedPlannedDate === null) || ($awardDate !== '' && $parsedAwardDate === null)) {
                throw new RuntimeException('Enter valid procurement dates.');
            }
            $projectCheck = db()->prepare('SELECT id FROM projects WHERE id = :id');
            $projectCheck->execute(['id' => (int) $projectId]);
            if (!$projectCheck->fetchColumn()) {
                throw new RuntimeException('Select a valid project.');
            }
            $pdo = db();
            $pdo->beginTransaction();
            try {
                $insert = $pdo->prepare(
                    'INSERT INTO procurement_records
                        (project_id, title, procurement_method, stage, supplier, reference, estimated_amount, contract_amount,
                         planned_date, award_date, notes, recorded_by)
                     VALUES
                        (:project_id, :title, :procurement_method, :stage, :supplier, :reference, :estimated_amount,
                         :contract_amount, :planned_date, :award_date, :notes, :recorded_by)'
                );
                $insert->execute([
                    'project_id' => (int) $projectId,
                    'title' => $title,
                    'procurement_method' => $methodValue,
                    'stage' => $stage,
                    'supplier' => $supplier !== '' ? $supplier : null,
                    'reference' => $reference !== '' ? $reference : null,
                    'estimated_amount' => $estimatedAmount !== '' ? $estimatedAmount : null,
                    'contract_amount' => $contractAmount !== '' ? $contractAmount : null,
                    'planned_date' => $parsedPlannedDate,
                    'award_date' => $parsedAwardDate,
                    'notes' => $notes !== '' ? $notes : null,
                    'recorded_by' => (int) $user['id'],
                ]);
                $recordId = (int) $pdo->lastInsertId();
                audit('procurement.recorded', $recordId, [
                    'project_id' => (int) $projectId,
                    'stage' => $stage,
                    'reference' => $reference,
                ]);
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $exception;
            }
            $_SESSION['flash'] = 'Procurement record saved.';
            redirect('procurement');
        }

        $projects = db()->query('SELECT id, project_code, title FROM projects ORDER BY title, id')->fetchAll();
        $projectOptions = '<option value="">Select a project</option>';
        foreach ($projects as $projectOption) {
            $projectOptions .= '<option value="' . (int) $projectOption['id'] . '">' . e($projectOption['project_code'] . ' · ' . $projectOption['title']) . '</option>';
        }
        $methodLabels = [
            'open_tender' => 'Open tender',
            'request_for_quotations' => 'Request for quotations',
            'direct_procurement' => 'Direct procurement',
            'framework' => 'Framework',
            'other' => 'Other',
        ];
        $stageLabels = [
            'planned' => 'Planned',
            'advertised' => 'Advertised',
            'evaluation' => 'Evaluation',
            'award_pending' => 'Award pending',
            'awarded' => 'Awarded',
            'contract_active' => 'Contract active',
            'completed' => 'Completed',
            'cancelled' => 'Cancelled',
        ];
        $methodOptions = '';
        foreach ($methodLabels as $value => $label) {
            $methodOptions .= '<option value="' . e($value) . '">' . e($label) . '</option>';
        }
        $stageOptions = '';
        foreach ($stageLabels as $value => $label) {
            $stageOptions .= '<option value="' . e($value) . '">' . e($label) . '</option>';
        }
        $records = db()->query(
            'SELECT r.*, p.project_code, p.title AS project_title, u.full_name AS recorder_name
             FROM procurement_records r
             INNER JOIN projects p ON p.id = r.project_id
             INNER JOIN users u ON u.id = r.recorded_by
             ORDER BY r.created_at DESC, r.id DESC LIMIT 500'
        )->fetchAll();
        $rows = '';
        foreach ($records as $record) {
            $stageCell = e($stageLabels[$record['stage']] ?? $record['stage']);
            if (has_permission($user, 'procurement.manage')) {
                $recordStageOptions = '';
                foreach ($stageLabels as $value => $label) {
                    $selected = $record['stage'] === $value ? ' selected' : '';
                    $recordStageOptions .= '<option value="' . e($value) . '"' . $selected . '>' . e($label) . '</option>';
                }
                $stageCell = '<form class="assignment-form" method="post" action="' . e(url('procurement')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="action" value="update_stage"><input type="hidden" name="record_id" value="' . (int) $record['id'] . '"><label class="visually-hidden" for="procurement-stage-' . (int) $record['id'] . '">Procurement stage</label><select id="procurement-stage-' . (int) $record['id'] . '" name="stage">' . $recordStageOptions . '</select><button class="small-button" type="submit">Update</button></form>';
            }
            $rows .= '<tr><td>' . e($record['project_code'] . ' · ' . $record['project_title']) . '</td><td>' . e($record['title']) . '</td><td>' . e($methodLabels[$record['procurement_method']] ?? $record['procurement_method']) . '</td><td>' . $stageCell . '</td><td>' . e($record['supplier']) . '</td><td>' . e($record['reference']) . '</td><td>' . e($record['contract_amount'] === null ? '' : number_format((float) $record['contract_amount'], 2)) . '</td><td>' . e($record['planned_date']) . '</td><td>' . e($record['award_date']) . '</td></tr>';
        }
        if ($rows === '') {
            $rows = '<tr><td colspan="9">No procurement records have been recorded.</td></tr>';
        }
        $form = has_permission($user, 'procurement.manage')
            ? '<section class="card"><h2>Record procurement activity</h2><form class="grid-form" method="post" action="' . e(url('procurement')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="action" value="add_procurement">'
                . '<label>Project<select name="project_id" required>' . $projectOptions . '</select></label><label>Procurement title<input name="title" maxlength="180" required></label>'
                . '<label>Method<select name="procurement_method" required>' . $methodOptions . '</select></label><label>Stage<select name="stage" required>' . $stageOptions . '</select></label>'
                . '<label>Supplier/contractor<input name="supplier" maxlength="180"></label><label>Tender/contract reference<input name="reference" maxlength="120"></label>'
                . '<label>Estimated amount (KES)<input type="number" name="estimated_amount" min="0" step="0.01"></label><label>Contract amount (KES)<input type="number" name="contract_amount" min="0" step="0.01"></label>'
                . '<label>Planned date<input type="date" name="planned_date"></label><label>Award date<input type="date" name="award_date"></label>'
                . '<label class="full-width">Notes<textarea name="notes" maxlength="20000" rows="3"></textarea></label>'
                . '<div class="form-actions"><button type="submit">Save procurement record</button></div></form></section>'
            : '';
        $content = '<section class="card"><p>These entries track procurement progress only. They do not constitute tender approval, award authorization, or a formal Municipal Board decision.</p></section>'
            . $form
            . '<section class="card"><div class="section-header"><h2>Procurement register</h2><a class="button secondary" href="' . e(url('procurement_export')) . '">Export CSV</a></div><div class="table-wrap"><table><thead><tr><th>Project</th><th>Procurement</th><th>Method</th><th>Stage</th><th>Supplier</th><th>Reference</th><th>Contract amount (KES)</th><th>Planned</th><th>Awarded</th></tr></thead><tbody>' . $rows . '</tbody></table></div></section>';
        render_page('Procurement', $content, $user, $message);
        exit;
    }

    if ($page === 'progress_reports') {
        if (!has_permission($user, 'progress_reports.view_all') && !has_permission($user, 'progress_reports.submit')) {
            require_permission($user, 'progress_reports.view_all');
        }

        if ($method === 'POST') {
            verify_csrf();
            $action = (string) ($_POST['action'] ?? '');
            if ($action === 'resubmit_report') {
                require_permission($user, 'progress_reports.submit');
                $reportId = filter_var($_POST['report_id'] ?? null, FILTER_VALIDATE_INT);
                $projectId = filter_var($_POST['project_id'] ?? null, FILTER_VALIDATE_INT);
                $percentInput = trim((string) ($_POST['percent_complete'] ?? ''));
                $percentComplete = filter_var($percentInput, FILTER_VALIDATE_FLOAT);
                $workCompleted = trim((string) ($_POST['work_completed'] ?? ''));
                $challenges = trim((string) ($_POST['challenges'] ?? ''));
                $nextSteps = trim((string) ($_POST['next_steps'] ?? ''));
                if (!$reportId || !$projectId || $percentComplete === false || $percentComplete < 0 || $percentComplete > 100) {
                    throw new RuntimeException('Enter a valid report and a percent complete between 0 and 100.');
                }
                if ($workCompleted === '' || strlen($workCompleted) > 20000 || strlen($challenges) > 20000 || strlen($nextSteps) > 20000) {
                    throw new RuntimeException('Describe the work completed and keep each report field under 20,000 characters.');
                }

                $pdo = db();
                $pdo->beginTransaction();
                try {
                    $reportQuery = $pdo->prepare(
                        'SELECT pr.id FROM project_progress_reports pr
                         INNER JOIN projects p ON p.id = pr.project_id
                         WHERE pr.id = :report_id AND pr.project_id = :project_id
                           AND pr.reported_by = :reported_by AND pr.review_status = \'changes_requested\'
                           AND p.project_manager_id = :project_manager_id
                         FOR UPDATE'
                    );
                    $reportQuery->execute([
                        'report_id' => (int) $reportId,
                        'project_id' => (int) $projectId,
                        'reported_by' => (int) $user['id'],
                        'project_manager_id' => (int) $user['id'],
                    ]);
                    if (!$reportQuery->fetchColumn()) {
                        throw new RuntimeException('Only your reports with requested changes can be resubmitted.');
                    }
                    $update = $pdo->prepare(
                        'UPDATE project_progress_reports
                         SET percent_complete = :percent_complete, work_completed = :work_completed,
                             challenges = :challenges, next_steps = :next_steps,
                             review_status = \'submitted\', review_note = NULL,
                             reviewed_by = NULL, reviewed_at = NULL
                         WHERE id = :id'
                    );
                    $update->execute([
                        'percent_complete' => $percentComplete,
                        'work_completed' => $workCompleted,
                        'challenges' => $challenges !== '' ? $challenges : null,
                        'next_steps' => $nextSteps !== '' ? $nextSteps : null,
                        'id' => (int) $reportId,
                    ]);
                    audit('progress_reports.resubmitted', (int) $reportId, [
                        'project_id' => (int) $projectId,
                        'percent_complete' => $percentComplete,
                    ]);
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }
                $_SESSION['flash'] = 'Updated progress report resubmitted for Municipal Manager review.';
                redirect('project', ['id' => (int) $projectId]);
            }

            if ($action === 'submit_report') {
                require_permission($user, 'progress_reports.submit');
                $projectId = filter_var($_POST['project_id'] ?? null, FILTER_VALIDATE_INT);
                $reportingDate = trim((string) ($_POST['reporting_date'] ?? ''));
                $percentInput = trim((string) ($_POST['percent_complete'] ?? ''));
                $percentComplete = filter_var($percentInput, FILTER_VALIDATE_FLOAT);
                $workCompleted = trim((string) ($_POST['work_completed'] ?? ''));
                $challenges = trim((string) ($_POST['challenges'] ?? ''));
                $nextSteps = trim((string) ($_POST['next_steps'] ?? ''));
                $parsedDate = DateTimeImmutable::createFromFormat('!Y-m-d', $reportingDate);
                if (!$projectId || !$parsedDate || $parsedDate->format('Y-m-d') !== $reportingDate) {
                    throw new RuntimeException('Enter a valid reporting date and project.');
                }
                if ($percentComplete === false || $percentComplete < 0 || $percentComplete > 100) {
                    throw new RuntimeException('Percent complete must be between 0 and 100.');
                }
                if ($workCompleted === '' || strlen($workCompleted) > 20000 || strlen($challenges) > 20000 || strlen($nextSteps) > 20000) {
                    throw new RuntimeException('Describe the work completed and keep each report field under 20,000 characters.');
                }

                $pdo = db();
                $pdo->beginTransaction();
                try {
                    $projectQuery = $pdo->prepare(
                        'SELECT id FROM projects WHERE id = :id'
                        . (has_permission($user, 'projects.view_all') ? '' : ' AND project_manager_id = :user_id')
                        . ' FOR UPDATE'
                    );
                    $projectParameters = ['id' => (int) $projectId];
                    if (!has_permission($user, 'projects.view_all')) {
                        $projectParameters['user_id'] = (int) $user['id'];
                    }
                    $projectQuery->execute($projectParameters);
                    if (!$projectQuery->fetchColumn()) {
                        throw new RuntimeException('Project not found or not assigned to your account.');
                    }
                    $insert = $pdo->prepare(
                        'INSERT INTO project_progress_reports
                         (project_id, reported_by, reporting_date, percent_complete, work_completed, challenges, next_steps)
                         VALUES (:project_id, :reported_by, :reporting_date, :percent_complete, :work_completed, :challenges, :next_steps)'
                    );
                    $insert->execute([
                        'project_id' => (int) $projectId,
                        'reported_by' => (int) $user['id'],
                        'reporting_date' => $reportingDate,
                        'percent_complete' => $percentComplete,
                        'work_completed' => $workCompleted,
                        'challenges' => $challenges !== '' ? $challenges : null,
                        'next_steps' => $nextSteps !== '' ? $nextSteps : null,
                    ]);
                    $reportId = (int) $pdo->lastInsertId();
                    audit('progress_reports.submitted', $reportId, [
                        'project_id' => (int) $projectId,
                        'reporting_date' => $reportingDate,
                        'percent_complete' => $percentComplete,
                    ]);
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }
                $_SESSION['flash'] = 'Progress report submitted for Municipal Manager review.';
                redirect('project', ['id' => (int) $projectId]);
            }

            require_permission($user, 'progress_reports.review');
            $reportId = filter_var($_POST['report_id'] ?? null, FILTER_VALIDATE_INT);
            $reviewNote = trim((string) ($_POST['review_note'] ?? ''));
            if (!$reportId || !in_array($action, ['recommend_for_board', 'request_changes'], true)) {
                throw new RuntimeException('Select a valid progress report and review action.');
            }
            if (($action === 'request_changes' && $reviewNote === '') || strlen($reviewNote) > 5000) {
                throw new RuntimeException('Provide a review note of up to 5,000 characters. A note is required when requesting changes.');
            }

            $pdo = db();
            $pdo->beginTransaction();
            try {
                $reportQuery = $pdo->prepare(
                    'SELECT review_status FROM project_progress_reports WHERE id = :id FOR UPDATE'
                );
                $reportQuery->execute(['id' => (int) $reportId]);
                $reportStatus = $reportQuery->fetchColumn();
                if ($reportStatus === false) {
                    throw new RuntimeException('That progress report does not exist.');
                }
                if ($reportStatus !== 'submitted') {
                    throw new RuntimeException('Only submitted progress reports can be reviewed.');
                }

                $status = $action === 'recommend_for_board' ? 'recommended_for_board' : 'changes_requested';
                $update = $pdo->prepare(
                    'UPDATE project_progress_reports
                     SET review_status = :status, review_note = :review_note,
                         reviewed_by = :reviewed_by, reviewed_at = NOW()
                     WHERE id = :id'
                );
                $update->execute([
                    'status' => $status,
                    'review_note' => $reviewNote !== '' ? $reviewNote : null,
                    'reviewed_by' => (int) $user['id'],
                    'id' => (int) $reportId,
                ]);
                audit(
                    $action === 'recommend_for_board' ? 'progress_reports.recommended_for_board' : 'progress_reports.changes_requested',
                    (int) $reportId,
                    ['review_note' => $reviewNote]
                );
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $exception;
            }

            $_SESSION['flash'] = $action === 'recommend_for_board'
                ? 'Report recommended for Municipal Board consideration. This is not a Board approval.'
                : 'Changes requested from the Project Manager.';
            redirect('progress_reports');
        }

        $conditions = [];
        $parameters = [];
        if (!has_permission($user, 'progress_reports.view_all')) {
            $conditions[] = 'pr.reported_by = :user_id';
            $parameters['user_id'] = (int) $user['id'];
        }
        $where = $conditions !== [] ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $reportsQuery = db()->prepare(
            'SELECT pr.*, p.project_code, p.title AS project_title,
                    reporter.full_name AS reporter_name, reviewer.full_name AS reviewer_name
             FROM project_progress_reports pr
             INNER JOIN projects p ON p.id = pr.project_id
             INNER JOIN users reporter ON reporter.id = pr.reported_by
             LEFT JOIN users reviewer ON reviewer.id = pr.reviewed_by
             ' . $where . '
             ORDER BY CASE WHEN pr.review_status = \'submitted\' THEN 0 ELSE 1 END,
                      pr.reporting_date DESC, pr.created_at DESC
             LIMIT 200'
        );
        $reportsQuery->execute($parameters);
        $reports = $reportsQuery->fetchAll();
        $reportCards = '';
        foreach ($reports as $report) {
            $statusLabels = [
                'submitted' => 'Awaiting Municipal Manager review',
                'changes_requested' => 'Changes requested',
                'recommended_for_board' => 'Recommended for Municipal Board',
            ];
            $reviewDetails = '';
            if ($report['review_note'] !== null && $report['review_note'] !== '') {
                $reviewDetails = '<p><strong>Review note:</strong> ' . nl2br(e($report['review_note'])) . '</p>';
            }
            if ($report['reviewer_name'] !== null) {
                $reviewDetails .= '<p class="muted">Reviewed by ' . e($report['reviewer_name']) . ' on ' . e($report['reviewed_at']) . '</p>';
            }
            $reviewForm = '';
            if (has_permission($user, 'progress_reports.review') && $report['review_status'] === 'submitted') {
                $reviewForm = '<form class="review-form" method="post" action="' . e(url('progress_reports')) . '">'
                    . '<input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
                    . '<input type="hidden" name="report_id" value="' . (int) $report['id'] . '">'
                    . '<label>Review note<textarea name="review_note" maxlength="5000" rows="3" placeholder="Required when requesting changes"></textarea></label>'
                    . '<div class="form-actions"><button name="action" value="recommend_for_board" type="submit">Recommend to Board</button>'
                    . '<button class="secondary" name="action" value="request_changes" type="submit">Request changes</button></div></form>';
            }
            $reportCards .= '<article class="card progress-report"><div class="report-heading"><div><h2><a href="' . e(url('project', ['id' => (int) $report['project_id']])) . '">' . e($report['project_title']) . '</a></h2>'
                . '<p class="muted">' . e($report['project_code']) . ' · Reported ' . e($report['reporting_date']) . ' by ' . e($report['reporter_name']) . '</p></div>'
                . '<span class="status">' . e($statusLabels[$report['review_status']] ?? $report['review_status']) . '</span></div>'
                . '<p><strong>' . e(number_format((float) $report['percent_complete'], 1)) . '% complete</strong></p>'
                . '<p><strong>Work completed:</strong><br>' . nl2br(e($report['work_completed'])) . '</p>'
                . ($report['challenges'] !== null && $report['challenges'] !== '' ? '<p><strong>Challenges:</strong><br>' . nl2br(e($report['challenges'])) . '</p>' : '')
                . ($report['next_steps'] !== null && $report['next_steps'] !== '' ? '<p><strong>Next steps:</strong><br>' . nl2br(e($report['next_steps'])) . '</p>' : '')
                . $reviewDetails . $reviewForm . '</article>';
        }
        if ($reportCards === '') {
            $reportCards = '<section class="card"><p>No progress reports are available yet.</p></section>';
        }
        if (has_permission($user, 'progress_reports.review')) {
            $intro = '<p class="muted">Review submissions and either request changes or recommend them for Municipal Board consideration. Recommendation is not final Board approval.</p>';
        } elseif (has_permission($user, 'progress_reports.view_all')) {
            $intro = '<p class="muted">Read-only view of progress reports across all projects.</p>';
        } else {
            $intro = '<p class="muted">Reports for your assigned projects are listed here after submission.</p>';
        }
        $intro .= '<p><a class="button secondary" href="' . e(url('progress_export')) . '">Export progress CSV</a></p>';
        render_page('Progress reports', $intro . $reportCards, $user, $message);
        exit;
    }

    if ($page === 'users') {
        require_permission($user, 'users.manage');
        if ($method === 'POST') {
            verify_csrf();
            $action = (string) ($_POST['action'] ?? '');
            if ($action === 'create_user') {
                $name = trim((string) ($_POST['full_name'] ?? ''));
                $email = strtolower(trim((string) ($_POST['email'] ?? '')));
                $roleId = filter_var($_POST['role_id'] ?? null, FILTER_VALIDATE_INT);
                $password = (string) ($_POST['password'] ?? '');
                if ($name === '' || strlen($name) > 150 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190 || !$roleId) {
                    throw new RuntimeException('Enter a valid name, email address and role.');
                }
                if (strlen($password) < 12) {
                    throw new RuntimeException('The initial password must be at least 12 characters.');
                }
                $roleCheck = db()->prepare('SELECT id FROM roles WHERE id = :id');
                $roleCheck->execute(['id' => $roleId]);
                if (!$roleCheck->fetchColumn()) {
                    throw new RuntimeException('Select a valid role.');
                }
                $pdo = db();
                $pdo->beginTransaction();
                try {
                    $insert = $pdo->prepare(
                        'INSERT INTO users (role_id, full_name, email, password_hash, created_by)
                         VALUES (:role_id, :full_name, :email, :password_hash, :created_by)'
                    );
                    $insert->execute([
                        'role_id' => $roleId,
                        'full_name' => $name,
                        'email' => $email,
                        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                        'created_by' => (int) $user['id'],
                    ]);
                    $id = (int) $pdo->lastInsertId();
                    audit('users.created', $id, ['role_id' => $roleId]);
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }
                $_SESSION['flash'] = 'Account created.';
                redirect('users');
            }

            if ($action === 'deactivate_user') {
                $targetId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
                if (!$targetId || (int) $targetId === (int) $user['id']) {
                    throw new RuntimeException('You cannot deactivate your own account.');
                }
                $pdo = db();
                $pdo->beginTransaction();
                try {
                    $targetRole = $pdo->prepare('SELECT role_id FROM users WHERE id = :id');
                    $targetRole->execute(['id' => $targetId]);
                    $targetRoleId = $targetRole->fetchColumn();
                    if ($targetRoleId === false) {
                        throw new RuntimeException('That account does not exist.');
                    }
                    $adminRole = $pdo->query("SELECT id FROM roles WHERE name = 'municipality_admin'")->fetchColumn();
                    if ((int) $targetRoleId === (int) $adminRole) {
                        $activeAdmins = $pdo->prepare(
                            'SELECT id FROM users WHERE role_id = :role_id AND is_active = 1 FOR UPDATE'
                        );
                        $activeAdmins->execute(['role_id' => (int) $adminRole]);
                        $adminIds = array_map('intval', $activeAdmins->fetchAll(PDO::FETCH_COLUMN));
                        if (!in_array((int) $targetId, $adminIds, true)) {
                            throw new RuntimeException('That account is not active.');
                        }
                        if (count($adminIds) <= 1) {
                            throw new RuntimeException('The last active Municipality Administrator cannot be deactivated.');
                        }
                    } else {
                        $target = $pdo->prepare(
                            'SELECT is_active FROM users WHERE id = :id AND role_id = :role_id FOR UPDATE'
                        );
                        $target->execute(['id' => $targetId, 'role_id' => (int) $targetRoleId]);
                        if (!(bool) $target->fetchColumn()) {
                            throw new RuntimeException('That account is not active.');
                        }
                        $managerRoleId = $pdo->query("SELECT id FROM roles WHERE name = 'project_manager'")->fetchColumn();
                        if ((int) $targetRoleId === (int) $managerRoleId) {
                            $assignedProjects = $pdo->prepare(
                                'SELECT COUNT(*) FROM projects WHERE project_manager_id = :user_id'
                            );
                            $assignedProjects->execute(['user_id' => (int) $targetId]);
                            if ((int) $assignedProjects->fetchColumn() > 0) {
                                throw new RuntimeException('Reassign this project manager’s projects before deactivating the account.');
                            }
                        }
                    }
                    $pdo->prepare('UPDATE users SET is_active = 0 WHERE id = :id')->execute(['id' => $targetId]);
                    audit('users.deactivated', (int) $targetId);
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }
                $_SESSION['flash'] = 'Account deactivated.';
                redirect('users');
            }
            throw new RuntimeException('Unknown account action.');
        }

        $users = db()->query(
            'SELECT u.id, u.full_name, u.email, u.is_active, u.created_at, r.display_name
             FROM users u INNER JOIN roles r ON r.id = u.role_id ORDER BY u.full_name'
        )->fetchAll();
        $rows = '';
        foreach ($users as $account) {
            $actionCell = (bool) $account['is_active'] && (int) $account['id'] !== (int) $user['id']
                ? '<form method="post" action="' . e(url('users')) . '" onsubmit="return confirm(\'Deactivate this account?\')"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="action" value="deactivate_user"><input type="hidden" name="user_id" value="' . (int) $account['id'] . '"><button class="danger" type="submit">Deactivate</button></form>'
                : '';
            $rows .= '<tr><td>' . e($account['full_name']) . '</td><td>' . e($account['email']) . '</td><td>' . e($account['display_name']) . '</td><td>' . ((bool) $account['is_active'] ? 'Active' : 'Inactive') . '</td><td>' . $actionCell . '</td></tr>';
        }
        $content = '<section class="card"><h2>Create account</h2><form class="grid-form" method="post" action="' . e(url('users')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="action" value="create_user">'
            . '<label>Full name<input name="full_name" maxlength="150" required></label><label>Email<input type="email" name="email" maxlength="190" required></label>'
            . '<label>Role<select name="role_id" required>' . role_options() . '</select></label><label>Password (12+ characters)<input type="password" name="password" minlength="12" required autocomplete="new-password"></label>'
            . '<div class="form-actions"><button type="submit">Create account</button></div></form></section>'
            . '<section class="card"><h2>Accounts</h2><div class="table-wrap"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table></div></section>';
        render_page('User accounts', $content, $user, $message);
        exit;
    }

    if ($page === 'projects') {
        require_permission($user, 'projects.view');
        if ($method === 'POST') {
            require_permission($user, 'projects.assign');
            verify_csrf();
            if ((string) ($_POST['action'] ?? '') !== 'reassign_manager') {
                throw new RuntimeException('Unknown project action.');
            }
            $projectId = filter_var($_POST['project_id'] ?? null, FILTER_VALIDATE_INT);
            $managerId = filter_var($_POST['project_manager_id'] ?? null, FILTER_VALIDATE_INT);
            if (!$projectId || !$managerId) {
                throw new RuntimeException('Select a project and an active project manager.');
            }

            $pdo = db();
            $pdo->beginTransaction();
            try {
                $managerCheck = $pdo->prepare(
                    'SELECT u.id FROM users u INNER JOIN roles r ON r.id = u.role_id
                     WHERE u.id = :id AND u.is_active = 1 AND r.name = :role
                     FOR UPDATE'
                );
                $managerCheck->execute(['id' => $managerId, 'role' => 'project_manager']);
                if (!$managerCheck->fetchColumn()) {
                    throw new RuntimeException('Select an active user with the Project Manager role.');
                }
                $projectCheck = $pdo->prepare('SELECT id FROM projects WHERE id = :id FOR UPDATE');
                $projectCheck->execute(['id' => $projectId]);
                if (!$projectCheck->fetchColumn()) {
                    throw new RuntimeException('That project does not exist.');
                }
                $update = $pdo->prepare('UPDATE projects SET project_manager_id = :manager_id WHERE id = :project_id');
                $update->execute(['manager_id' => $managerId, 'project_id' => $projectId]);
                audit('projects.manager_reassigned', (int) $projectId, ['project_manager_id' => (int) $managerId]);
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $exception;
            }
            $_SESSION['flash'] = 'Project manager reassigned.';
            redirect('projects');
        }

        $search = trim((string) ($_GET['q'] ?? ''));
        $status = (string) ($_GET['status'] ?? '');
        $department = trim((string) ($_GET['department'] ?? ''));
        $sort = (string) ($_GET['sort'] ?? 'updated');
        $currentPage = filter_var($_GET['p'] ?? 1, FILTER_VALIDATE_INT);
        if (!in_array($status, ['', 'planned', 'active', 'closed'], true)) {
            throw new RuntimeException('Select a valid project status filter.');
        }
        if (strlen($search) > 100 || strlen($department) > 150) {
            throw new RuntimeException('Search or department filter is too long.');
        }
        if (!in_array($sort, ['updated', 'title', 'status'], true) || !$currentPage || $currentPage < 1) {
            throw new RuntimeException('Choose a valid sort order and project-register page.');
        }

        $managers = [];
        if (has_permission($user, 'projects.assign')) {
            $managers = db()->query(
                "SELECT u.id, u.full_name FROM users u
                 INNER JOIN roles r ON r.id = u.role_id
                 WHERE u.is_active = 1 AND r.name = 'project_manager'
                 ORDER BY u.full_name"
            )->fetchAll();
        }
        $conditions = [];
        $parameters = [];
        if (!has_permission($user, 'projects.view_all')) {
            $conditions[] = 'p.project_manager_id = :user_id';
            $parameters['user_id'] = (int) $user['id'];
        }
        if ($search !== '') {
            $escapedSearch = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $search);
            $conditions[] = '(p.project_code LIKE :search_code OR p.title LIKE :search_title OR p.department LIKE :search_department OR u.full_name LIKE :search_manager)';
            $searchValue = '%' . $escapedSearch . '%';
            $parameters['search_code'] = $searchValue;
            $parameters['search_title'] = $searchValue;
            $parameters['search_department'] = $searchValue;
            $parameters['search_manager'] = $searchValue;
        }
        if ($status !== '') {
            $conditions[] = 'p.status = :status';
            $parameters['status'] = $status;
        }
        if ($department !== '') {
            $conditions[] = 'p.department = :department';
            $parameters['department'] = $department;
        }
        $where = $conditions !== [] ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $countStatement = db()->prepare(
            'SELECT COUNT(*) FROM projects p
             INNER JOIN users u ON u.id = p.project_manager_id ' . $where
        );
        $countStatement->execute($parameters);
        $filteredCount = (int) $countStatement->fetchColumn();
        $pageSize = 15;
        $pageCount = max(1, (int) ceil($filteredCount / $pageSize));
        $currentPage = min((int) $currentPage, $pageCount);
        $offset = ($currentPage - 1) * $pageSize;
        $orderBy = [
            'updated' => 'p.updated_at DESC, p.id DESC',
            'title' => 'p.title ASC, p.id ASC',
            'status' => 'FIELD(p.status, \'active\', \'planned\', \'closed\'), p.updated_at DESC',
        ][$sort];
        $statement = db()->prepare(
            'SELECT p.*, u.full_name AS manager_name,
                    (SELECT pr.percent_complete FROM project_progress_reports pr
                     WHERE pr.project_id = p.id
                     ORDER BY pr.reporting_date DESC, pr.created_at DESC LIMIT 1) AS latest_progress
             FROM projects p
             INNER JOIN users u ON u.id = p.project_manager_id
             ' . $where . ' ORDER BY ' . $orderBy . ' LIMIT ' . $pageSize . ' OFFSET ' . $offset
        );
        $statement->execute($parameters);
        $projects = $statement->fetchAll();

        $departmentsQuery = 'SELECT DISTINCT department FROM projects WHERE department IS NOT NULL AND department <> \'\'';
        if (!has_permission($user, 'projects.view_all')) {
            $departmentsQuery .= ' AND project_manager_id = ' . (int) $user['id'];
        }
        $departments = db()->query($departmentsQuery . ' ORDER BY department')->fetchAll(PDO::FETCH_COLUMN);

        $departmentOptions = '<option value="">All departments</option>';
        foreach ($departments as $availableDepartment) {
            $selected = $department === $availableDepartment ? ' selected' : '';
            $departmentOptions .= '<option value="' . e($availableDepartment) . '"' . $selected . '>' . e($availableDepartment) . '</option>';
        }
        $statusOptions = [
            '' => 'All statuses',
            'planned' => 'Planned',
            'active' => 'In progress',
            'closed' => 'Closed',
        ];
        $statusSelect = '';
        foreach ($statusOptions as $value => $label) {
            $selected = $status === $value ? ' selected' : '';
            $statusSelect .= '<option value="' . e($value) . '"' . $selected . '>' . e($label) . '</option>';
        }
        $sortOptions = [
            'updated' => 'Recently updated',
            'title' => 'Project title',
            'status' => 'Status',
        ];
        $sortSelect = '';
        foreach ($sortOptions as $value => $label) {
            $selected = $sort === $value ? ' selected' : '';
            $sortSelect .= '<option value="' . e($value) . '"' . $selected . '>' . e($label) . '</option>';
        }

        $rows = '';
        foreach ($projects as $project) {
            $assignmentCell = '';
            if (has_permission($user, 'projects.assign')) {
                $managerOptions = '';
                foreach ($managers as $manager) {
                    $selected = (int) $manager['id'] === (int) $project['project_manager_id'] ? ' selected' : '';
                    $managerOptions .= '<option value="' . (int) $manager['id'] . '"' . $selected . '>' . e($manager['full_name']) . '</option>';
                }
                $assignmentCell = '<form class="assignment-form" method="post" action="' . e(url('projects')) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="action" value="reassign_manager"><input type="hidden" name="project_id" value="' . (int) $project['id'] . '"><select aria-label="Project manager" name="project_manager_id" required>' . $managerOptions . '</select><button type="submit">Reassign</button></form>';
            }
            $title = '<a href="' . e(url('project', ['id' => (int) $project['id']])) . '">' . e($project['title']) . '</a>';
            $editCell = has_permission($user, 'projects.update')
                ? '<a class="button small-button secondary" href="' . e(url('project_edit', ['id' => (int) $project['id']])) . '">Edit</a>'
                : '';
            $assignmentColumn = has_permission($user, 'projects.assign') ? '<td>' . $assignmentCell . '</td>' : '';
            $progress = $project['latest_progress'] !== null ? (float) $project['latest_progress'] : null;
            $progressCell = $progress === null
                ? '<div class="project-progress-cell"><span>No report</span></div>'
                : '<div class="project-progress-cell"><div class="progress-track"><div class="progress-fill" style="width:' . e((string) $progress) . '%"></div></div><span>' . e(number_format($progress, 0)) . '% complete</span></div>';
            $statusClass = 'status-' . $project['status'];
            $statusLabel = $project['status'] === 'active' ? 'In progress' : ucfirst($project['status']);
            $rows .= '<tr><td><span class="project-code">' . e($project['project_code']) . '</span></td><td><div class="project-title-cell">' . $title . '<span class="muted">' . e($project['department'] !== '' ? $project['department'] : 'No department') . '</span></div></td><td>' . e($project['manager_name']) . '</td><td>' . $progressCell . '</td><td><span class="status ' . e($statusClass) . '">' . e($statusLabel) . '</span></td>' . $assignmentColumn . '<td>' . $editCell . '</td></tr>';
        }
        if ($rows === '') {
            $columnCount = has_permission($user, 'projects.assign') ? '6' : '5';
            $rows = '<tr><td colspan="' . $columnCount . '"><div class="empty-state">No projects match your filters.</div></td></tr>';
        }
        $pagination = '';
        if ($pageCount > 1) {
            $pagination .= '<div class="pagination"><span>Page ' . $currentPage . ' of ' . $pageCount . '</span><div>';
            if ($currentPage > 1) {
                $pagination .= '<a class="button secondary small-button" href="' . e(url('projects', ['q' => $search, 'status' => $status, 'department' => $department, 'sort' => $sort, 'p' => $currentPage - 1])) . '">Previous</a>';
            }
            if ($currentPage < $pageCount) {
                $pagination .= '<a class="button secondary small-button" href="' . e(url('projects', ['q' => $search, 'status' => $status, 'department' => $department, 'sort' => $sort, 'p' => $currentPage + 1])) . '">Next</a>';
            }
            $pagination .= '</div></div>';
        }
        $content = '<div class="project-register-toolbar"><p>' . $filteredCount . ' project' . ($filteredCount === 1 ? '' : 's') . ' in this view</p><div>'
            . '<a class="button secondary" href="' . e(url('projects_export')) . '">Export CSV</a> '
            . (has_permission($user, 'projects.create') ? '<a class="button" href="' . e(url('project_new')) . '">Create project</a>' : '') . '</div></div>'
            . '<section class="card"><form class="filter-form" method="get" action="' . e(url('projects')) . '"><input type="hidden" name="page" value="projects">'
            . '<label>Search<input name="q" value="' . e($search) . '" maxlength="100" placeholder="Code, project, department or manager"></label>'
            . '<label>Department<select name="department">' . $departmentOptions . '</select></label><label>Status<select name="status">' . $statusSelect . '</select></label>'
            . '<label>Sort by<select name="sort">' . $sortSelect . '</select></label>'
            . '<div class="filter-actions"><button type="submit">Apply filters</button> <a class="button secondary" href="' . e(url('projects')) . '">Clear</a></div></form></section>'
            . '<section class="card"><div class="table-wrap"><table><thead><tr><th>Project</th><th>Manager</th><th>Progress</th><th>Status</th>' . (has_permission($user, 'projects.assign') ? '<th>Assignment</th>' : '') . '<th>Actions</th></tr></thead><tbody>' . $rows . '</tbody></table></div>'
            . $pagination . '</section>';
        render_page('Projects', $content, $user, $message);
        exit;
    }

    if ($page === 'project' || $page === 'project_edit') {
        require_permission($user, 'projects.view');
        $projectId = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT);
        if (!$projectId) {
            http_response_code(404);
            throw new RuntimeException('Project not found.');
        }

        $projectQuery = db()->prepare(
            'SELECT p.*, manager.full_name AS manager_name, creator.full_name AS creator_name
             FROM projects p
             INNER JOIN users manager ON manager.id = p.project_manager_id
             INNER JOIN users creator ON creator.id = p.created_by
             WHERE p.id = :project_id'
             . (has_permission($user, 'projects.view_all') ? '' : ' AND p.project_manager_id = :user_id')
        );
        $projectParameters = ['project_id' => (int) $projectId];
        if (!has_permission($user, 'projects.view_all')) {
            $projectParameters['user_id'] = (int) $user['id'];
        }
        $projectQuery->execute($projectParameters);
        $project = $projectQuery->fetch();
        if (!$project) {
            http_response_code(404);
            throw new RuntimeException('Project not found.');
        }

        if ($page === 'project_edit') {
            require_permission($user, 'projects.update');
            if ($method === 'POST') {
                verify_csrf();
                $title = trim((string) ($_POST['title'] ?? ''));
                $description = trim((string) ($_POST['description'] ?? ''));
                $department = trim((string) ($_POST['department'] ?? ''));
                $location = trim((string) ($_POST['location'] ?? ''));
                $status = (string) ($_POST['status'] ?? '');
                if ($title === '' || strlen($title) > 180) {
                    throw new RuntimeException('Enter a project title of no more than 180 characters.');
                }
                if (strlen($description) > 20000 || strlen($department) > 150 || strlen($location) > 180) {
                    throw new RuntimeException('One or more project fields exceed the allowed length.');
                }
                if (!in_array($status, ['planned', 'active', 'closed'], true)) {
                    throw new RuntimeException('Select a valid project status.');
                }

                $pdo = db();
                $pdo->beginTransaction();
                try {
                    $lockQuery = $pdo->prepare(
                        'SELECT p.title, p.description, p.department, p.location, p.status
                         FROM projects p WHERE p.id = :project_id'
                         . (has_permission($user, 'projects.view_all') ? '' : ' AND p.project_manager_id = :user_id')
                         . ' FOR UPDATE'
                    );
                    $lockParameters = ['project_id' => (int) $projectId];
                    if (!has_permission($user, 'projects.view_all')) {
                        $lockParameters['user_id'] = (int) $user['id'];
                    }
                    $lockQuery->execute($lockParameters);
                    $before = $lockQuery->fetch();
                    if (!$before) {
                        throw new RuntimeException('Project not found or no longer assigned to your account.');
                    }
                    $after = [
                        'title' => $title,
                        'description' => $description !== '' ? $description : null,
                        'department' => $department !== '' ? $department : null,
                        'location' => $location !== '' ? $location : null,
                        'status' => $status,
                    ];
                    $changes = [];
                    foreach ($after as $field => $value) {
                        $oldValue = $before[$field] === '' ? null : $before[$field];
                        if ($oldValue !== $value) {
                            $changes[$field] = ['from' => $oldValue, 'to' => $value];
                        }
                    }

                    if ($changes !== []) {
                        $update = $pdo->prepare(
                            'UPDATE projects
                             SET title = :title, description = :description, department = :department,
                                 location = :location, status = :status
                             WHERE id = :project_id'
                        );
                        $update->execute($after + ['project_id' => (int) $projectId]);
                        audit('projects.updated', (int) $projectId, ['changes' => $changes]);
                    }
                    $pdo->commit();
                } catch (Throwable $exception) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    throw $exception;
                }

                $_SESSION['flash'] = $changes === [] ? 'No project details were changed.' : 'Project details updated.';
                redirect('project', ['id' => (int) $projectId]);
            }

            $content = '<section class="card"><form class="grid-form" method="post" action="' . e(url('project_edit', ['id' => (int) $projectId])) . '"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
                . '<p class="full-width"><strong>Project code:</strong> ' . e($project['project_code']) . ' <span class="muted">Codes are fixed after creation.</span></p>'
                . '<label>Project title<input name="title" maxlength="180" required value="' . e($project['title']) . '"></label>'
                . '<label>Department<input name="department" maxlength="150" value="' . e($project['department']) . '"></label>'
                . '<label>Location<input name="location" maxlength="180" value="' . e($project['location']) . '"></label>'
                . '<label>Status<select name="status" required>'
                . '<option value="planned"' . ($project['status'] === 'planned' ? ' selected' : '') . '>Planned</option>'
                . '<option value="active"' . ($project['status'] === 'active' ? ' selected' : '') . '>In progress</option>'
                . '<option value="closed"' . ($project['status'] === 'closed' ? ' selected' : '') . '>Closed</option>'
                . '</select></label>'
                . '<label class="full-width">Description<textarea name="description" maxlength="20000" rows="6">' . e($project['description']) . '</textarea></label>'
                . '<p class="full-width muted">Changing a project status updates the register and dashboard counts. This does not constitute formal project approval.</p>'
                . '<div class="form-actions"><button type="submit">Save changes</button><a class="button secondary" href="' . e(url('project', ['id' => (int) $projectId])) . '">Cancel</a></div></form></section>';
            render_page('Edit project', $content, $user, $message);
            exit;
        }

        $progressSection = '';
        if (has_permission($user, 'progress_reports.submit') || has_permission($user, 'progress_reports.view_all')) {
            $reportQuery = db()->prepare(
                'SELECT pr.*, reporter.full_name AS reporter_name, reviewer.full_name AS reviewer_name
                 FROM project_progress_reports pr
                 INNER JOIN users reporter ON reporter.id = pr.reported_by
                 LEFT JOIN users reviewer ON reviewer.id = pr.reviewed_by
                 WHERE pr.project_id = :project_id
                 ORDER BY pr.reporting_date DESC, pr.created_at DESC'
            );
            $reportQuery->execute(['project_id' => (int) $projectId]);
            $reportHistory = '';
            foreach ($reportQuery->fetchAll() as $report) {
                $reportStatuses = [
                    'submitted' => 'Awaiting review',
                    'changes_requested' => 'Changes requested',
                    'recommended_for_board' => 'Recommended for Board',
                ];
                $reviewLine = $report['review_note'] !== null && $report['review_note'] !== ''
                    ? '<p><strong>Review note:</strong> ' . nl2br(e($report['review_note'])) . '</p>'
                    : '';
                if ($report['reviewer_name'] !== null) {
                    $reviewLine .= '<p class="muted">Reviewed by ' . e($report['reviewer_name']) . ' · ' . e($report['reviewed_at']) . '</p>';
                }
                $resubmitForm = '';
                if (
                    has_permission($user, 'progress_reports.submit')
                    && (int) $report['reported_by'] === (int) $user['id']
                    && $report['review_status'] === 'changes_requested'
                ) {
                    $resubmitForm = '<form class="review-form" method="post" action="' . e(url('progress_reports')) . '">'
                        . '<input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
                        . '<input type="hidden" name="action" value="resubmit_report">'
                        . '<input type="hidden" name="report_id" value="' . (int) $report['id'] . '">'
                        . '<input type="hidden" name="project_id" value="' . (int) $projectId . '">'
                        . '<div class="grid-form"><label>Updated percent complete<input type="number" name="percent_complete" min="0" max="100" step="0.1" required value="' . e((string) $report['percent_complete']) . '"></label>'
                        . '<label class="full-width">Updated work completed<textarea name="work_completed" maxlength="20000" rows="4" required>' . e($report['work_completed']) . '</textarea></label>'
                        . '<label>Updated challenges<textarea name="challenges" maxlength="20000" rows="3">' . e($report['challenges']) . '</textarea></label>'
                        . '<label>Updated next steps<textarea name="next_steps" maxlength="20000" rows="3">' . e($report['next_steps']) . '</textarea></label>'
                        . '<div class="form-actions"><button type="submit">Resubmit report</button></div></div></form>';
                }
                $reportHistory .= '<article class="report-entry"><div class="report-heading"><strong>' . e($report['reporting_date']) . ' · ' . e($report['reporter_name']) . '</strong>'
                    . '<span class="status">' . e($reportStatuses[$report['review_status']] ?? $report['review_status']) . '</span></div>'
                    . '<p><strong>' . e(number_format((float) $report['percent_complete'], 1)) . '% complete</strong></p>'
                    . '<p><strong>Work completed:</strong><br>' . nl2br(e($report['work_completed'])) . '</p>'
                    . ($report['challenges'] !== null && $report['challenges'] !== '' ? '<p><strong>Challenges:</strong><br>' . nl2br(e($report['challenges'])) . '</p>' : '')
                    . ($report['next_steps'] !== null && $report['next_steps'] !== '' ? '<p><strong>Next steps:</strong><br>' . nl2br(e($report['next_steps'])) . '</p>' : '')
                    . $reviewLine . $resubmitForm . '</article>';
            }
            if ($reportHistory === '') {
                $reportHistory = '<p>No progress reports have been submitted for this project.</p>';
            }
            $newReportForm = '';
            if (has_permission($user, 'progress_reports.submit')) {
                $newReportForm = '<h2>Submit a progress report</h2><form method="post" action="' . e(url('progress_reports')) . '">'
                    . '<input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
                    . '<input type="hidden" name="action" value="submit_report"><input type="hidden" name="project_id" value="' . (int) $projectId . '">'
                    . '<div class="grid-form"><label>Reporting date<input type="date" name="reporting_date" required value="' . e(date('Y-m-d')) . '"></label>'
                    . '<label>Percent complete<input type="number" name="percent_complete" min="0" max="100" step="0.1" required></label>'
                    . '<label class="full-width">Work completed<textarea name="work_completed" maxlength="20000" rows="4" required></textarea></label>'
                    . '<label>Challenges<textarea name="challenges" maxlength="20000" rows="3"></textarea></label>'
                    . '<label>Next steps<textarea name="next_steps" maxlength="20000" rows="3"></textarea></label>'
                    . '<div class="form-actions"><button type="submit">Submit report</button></div></div></form>';
            }
            $progressSection = '<section class="card" id="progress"><h2>Progress reporting</h2>'
                . '<p class="muted">Municipal Manager review may recommend a report for Municipal Board consideration or request changes; it is not final Board approval.</p>'
                . $newReportForm . '<div class="report-history">' . $reportHistory . '</div></section>';
        }

        $documentSection = '';
        if (has_permission($user, 'documents.view')) {
            $documentQuery = db()->prepare(
                'SELECT d.id, d.original_name, d.media_type, d.size_bytes, d.description, d.created_at, u.full_name AS uploader_name
                 FROM project_documents d
                 INNER JOIN users u ON u.id = d.uploaded_by
                 WHERE d.project_id = :project_id
                 ORDER BY d.created_at DESC, d.id DESC'
            );
            $documentQuery->execute(['project_id' => (int) $projectId]);
            $documentRows = '';
            foreach ($documentQuery->fetchAll() as $document) {
                $imagePreviewAttribute = in_array($document['media_type'], ['image/jpeg', 'image/png'], true) ? ' data-evidence-image' : '';
                $documentRows .= '<tr><td><a href="' . e(url('document_download', ['id' => (int) $document['id']])) . '"' . $imagePreviewAttribute . '>' . e($document['original_name']) . '</a>'
                    . ($document['description'] !== null && $document['description'] !== '' ? '<div class="muted">' . e($document['description']) . '</div>' : '')
                    . '</td><td>' . e(number_format((int) $document['size_bytes'] / 1024, 1)) . ' KB</td><td>' . e($document['uploader_name']) . '</td><td>' . e($document['created_at']) . '</td></tr>';
            }
            if ($documentRows === '') {
                $documentRows = '<tr><td colspan="4">No evidence documents have been uploaded for this project.</td></tr>';
            }
            $uploadForm = has_permission($user, 'documents.upload')
                ? '<h3>Upload project evidence</h3><form class="grid-form" method="post" enctype="multipart/form-data" action="' . e(url('document_upload')) . '">'
                    . '<input type="hidden" name="_csrf" value="' . e(csrf_token()) . '"><input type="hidden" name="project_id" value="' . (int) $projectId . '">'
                    . '<label>Evidence file<input type="file" name="document" accept=".pdf,.jpg,.jpeg,.png,.mp4,.webm,application/pdf,image/jpeg,image/png,video/mp4,video/webm" required></label>'
                    . '<div class="media-preview full-width" data-media-preview hidden aria-live="polite"></div>'
                    . '<label>Description (optional)<input name="description" maxlength="500"></label>'
                    . '<p class="full-width muted">Upload photos or short videos as proof of completion. Accepts PDF, JPG, PNG, MP4, and WEBM up to 50 MB. Files are stored privately and require your project access to view them.</p>'
                    . '<div class="form-actions"><button type="submit">Upload evidence</button></div></form>'
                : '';
            $documentSection = '<section class="card"><h2>Evidence documents</h2>'
                . $uploadForm
                . '<div class="table-wrap"><table><thead><tr><th>Document</th><th>Size</th><th>Uploaded by</th><th>Uploaded</th></tr></thead><tbody>' . $documentRows . '</tbody></table></div></section>';
        }

        $projectTabs = $progressSection !== ''
            ? '<nav class="project-tabs" aria-label="Project workspace tabs"><a class="active" href="#overview">Overview</a><a href="#progress">Progress</a></nav>'
            : '';
        $content = $projectTabs . '<section class="card" id="overview"><dl class="project-details">'
            . '<dt>Project code</dt><dd>' . e($project['project_code']) . '</dd>'
            . '<dt>Project title</dt><dd>' . e($project['title']) . '</dd>'
            . '<dt>Status</dt><dd><span class="status status-' . e($project['status']) . '">' . e($project['status'] === 'active' ? 'In progress' : ucfirst($project['status'])) . '</span></dd>'
            . '<dt>Department</dt><dd>' . e($project['department'] !== '' ? $project['department'] : 'Not specified') . '</dd>'
            . '<dt>Location</dt><dd>' . e($project['location'] !== '' ? $project['location'] : 'Not specified') . '</dd>'
            . '<dt>Project manager</dt><dd>' . e($project['manager_name']) . '</dd>'
            . '<dt>Created by</dt><dd>' . e($project['creator_name']) . '</dd>'
            . '<dt>Created</dt><dd>' . e($project['created_at']) . '</dd>'
            . '<dt>Last updated</dt><dd>' . e($project['updated_at']) . '</dd>'
            . '<dt>Description</dt><dd class="description-text">' . nl2br(e($project['description'] !== '' ? $project['description'] : 'No description provided.')) . '</dd>'
            . '</dl><p><a class="button secondary" href="' . e(url('projects')) . '">Back to projects</a> '
            . (has_permission($user, 'projects.update') ? '<a class="button" href="' . e(url('project_edit', ['id' => (int) $projectId])) . '">Edit project</a>' : '')
            . '</p></section>' . $documentSection . $progressSection;
        render_page('Project details', $content, $user, $message);
        exit;
    }

    if ($page === 'project_new') {
        require_permission($user, 'projects.create');
        if ($method === 'POST') {
            verify_csrf();
            $code = strtoupper(trim((string) ($_POST['project_code'] ?? '')));
            $title = trim((string) ($_POST['title'] ?? ''));
            $description = trim((string) ($_POST['description'] ?? ''));
            $department = trim((string) ($_POST['department'] ?? ''));
            $location = trim((string) ($_POST['location'] ?? ''));
            $managerId = filter_var($_POST['project_manager_id'] ?? null, FILTER_VALIDATE_INT);

            if (!preg_match('/^[A-Z0-9][A-Z0-9_-]{1,39}$/', $code) || $title === '' || strlen($title) > 180) {
                throw new RuntimeException('Enter a project code (2–40 letters, numbers, hyphens or underscores) and a title.');
            }
            if (strlen($description) > 20000 || strlen($department) > 150 || strlen($location) > 180) {
                throw new RuntimeException('One or more project fields exceed the allowed length.');
            }
            if (has_permission($user, 'users.manage')) {
                if (!$managerId) {
                    throw new RuntimeException('Select a project manager.');
                }
            } else {
                $managerId = (int) $user['id'];
            }

            $projectMedia = $_FILES['project_media'] ?? null;
            $projectMediaInfo = null;
            if (is_array($projectMedia)) {
                if (!isset($projectMedia['error'], $projectMedia['tmp_name'], $projectMedia['name'])) {
                    throw new RuntimeException('Choose a valid project photo or video.');
                }
                if ((int) $projectMedia['error'] !== UPLOAD_ERR_OK && (int) $projectMedia['error'] !== UPLOAD_ERR_NO_FILE) {
                    $uploadErrors = [
                        UPLOAD_ERR_INI_SIZE => 'The project media exceeds the server upload limit.',
                        UPLOAD_ERR_FORM_SIZE => 'The project media exceeds the 50 MB upload limit.',
                        UPLOAD_ERR_PARTIAL => 'The project media upload was incomplete. Try again.',
                        UPLOAD_ERR_NO_FILE => 'No project media was selected.',
                        UPLOAD_ERR_NO_TMP_DIR => 'The server upload temporary directory is unavailable.',
                        UPLOAD_ERR_CANT_WRITE => 'The server could not store the uploaded project media.',
                        UPLOAD_ERR_EXTENSION => 'A server extension prevented the project media upload.',
                    ];
                    throw new RuntimeException($uploadErrors[(int) $projectMedia['error']] ?? 'The project media upload failed.');
                }
                if ((int) $projectMedia['error'] === UPLOAD_ERR_OK) {
                    if (!is_uploaded_file((string) $projectMedia['tmp_name'])) {
                        throw new RuntimeException('The uploaded project media could not be verified.');
                    }
                    $fileSize = filesize((string) $projectMedia['tmp_name']);
                    if ($fileSize === false || $fileSize < 1 || $fileSize > 50 * 1024 * 1024) {
                        throw new RuntimeException('Choose a project photo or video smaller than or equal to 50 MB.');
                    }
                    if (!class_exists('finfo')) {
                        throw new RuntimeException('File type validation is unavailable. Enable the PHP Fileinfo extension.');
                    }
                    $fileInfo = new finfo(FILEINFO_MIME_TYPE);
                    $mediaType = $fileInfo->file((string) $projectMedia['tmp_name']);
                    $allowedTypes = [
                        'image/jpeg' => ['jpg', 'jpeg'],
                        'image/png' => ['png'],
                        'video/mp4' => ['mp4'],
                        'video/webm' => ['webm'],
                    ];
                    $originalName = basename(str_replace('\\', '/', (string) $projectMedia['name']));
                    $originalName = preg_replace('/[\x00-\x1F\x7F]/u', '', $originalName) ?? '';
                    $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
                    if (!is_string($mediaType) || !isset($allowedTypes[$mediaType]) || !in_array($extension, $allowedTypes[$mediaType], true)) {
                        throw new RuntimeException('Only JPG, PNG, MP4, and WEBM files are accepted for project media.');
                    }
                    $privateRoot = private_storage_path();
                    if (!is_dir($privateRoot) && !mkdir($privateRoot, 0700, true) && !is_dir($privateRoot)) {
                        throw new RuntimeException('Private evidence storage could not be created.');
                    }
                    $storageName = bin2hex(random_bytes(16)) . '.' . $allowedTypes[$mediaType][0];
                    $storedPath = $privateRoot . DIRECTORY_SEPARATOR . $storageName;
                    if (!move_uploaded_file((string) $projectMedia['tmp_name'], $storedPath)) {
                        throw new RuntimeException('The server could not move the project media into private storage.');
                    }
                    $fileHash = hash_file('sha256', $storedPath);
                    if (!is_string($fileHash)) {
                        unlink($storedPath);
                        throw new RuntimeException('The server could not verify the stored project media.');
                    }
                    $projectMediaInfo = [
                        'original_name' => $originalName,
                        'storage_name' => $storageName,
                        'media_type' => $mediaType,
                        'size_bytes' => (int) $fileSize,
                        'sha256' => $fileHash,
                        'description' => 'Project photo or video',
                    ];
                }
            }
            $pdo = db();
            $pdo->beginTransaction();
            try {
                $managerStatement = $pdo->prepare(
                    'SELECT u.id FROM users u INNER JOIN roles r ON r.id = u.role_id
                     WHERE u.id = :id AND u.is_active = 1 AND r.name = :role
                     FOR UPDATE'
                );
                $managerStatement->execute(['id' => $managerId, 'role' => 'project_manager']);
                if (!$managerStatement->fetchColumn()) {
                    throw new RuntimeException('Select an active user with the Project Manager role.');
                }
                $insert = $pdo->prepare(
                    'INSERT INTO projects (project_code, title, description, department, location, status, project_manager_id, created_by)
                     VALUES (:project_code, :title, :description, :department, :location, :status, :manager_id, :created_by)'
                );
                $insert->execute([
                    'project_code' => $code,
                    'title' => $title,
                    'description' => $description !== '' ? $description : null,
                    'department' => $department !== '' ? $department : null,
                    'location' => $location !== '' ? $location : null,
                    'status' => 'planned',
                    'manager_id' => $managerId,
                    'created_by' => (int) $user['id'],
                ]);
                $projectId = (int) $pdo->lastInsertId();
                if ($projectMediaInfo !== null) {
                    $projectMediaInsert = $pdo->prepare(
                        'INSERT INTO project_documents
                            (project_id, original_name, storage_name, media_type, size_bytes, sha256, description, uploaded_by)
                         VALUES
                            (:project_id, :original_name, :storage_name, :media_type, :size_bytes, :sha256, :description, :uploaded_by)'
                    );
                    $projectMediaInsert->execute([
                        'project_id' => $projectId,
                        'original_name' => $projectMediaInfo['original_name'],
                        'storage_name' => $projectMediaInfo['storage_name'],
                        'media_type' => $projectMediaInfo['media_type'],
                        'size_bytes' => $projectMediaInfo['size_bytes'],
                        'sha256' => $projectMediaInfo['sha256'],
                        'description' => $projectMediaInfo['description'],
                        'uploaded_by' => (int) $user['id'],
                    ]);
                }
                audit('projects.created', $projectId, [
                    'project_code' => $code,
                    'project_manager_id' => (int) $managerId,
                ]);
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                if ($projectMediaInfo !== null) {
                    $uploadedPath = private_storage_path() . DIRECTORY_SEPARATOR . $projectMediaInfo['storage_name'];
                    if (is_file($uploadedPath)) {
                        unlink($uploadedPath);
                    }
                }
                throw $exception;
            }
            $_SESSION['flash'] = 'Project created and assigned.';
            redirect('projects');
        }

        $managerOptions = '';
        if (has_permission($user, 'users.manage')) {
            $managers = db()->query(
                "SELECT u.id, u.full_name FROM users u
                 INNER JOIN roles r ON r.id = u.role_id
                 WHERE u.is_active = 1 AND r.name = 'project_manager'
                 ORDER BY u.full_name"
            )->fetchAll();
            foreach ($managers as $manager) {
                $managerOptions .= '<option value="' . (int) $manager['id'] . '">' . e($manager['full_name']) . '</option>';
            }
            if ($managerOptions === '') {
                $content = '<section class="card narrow"><p>There are no active Project Manager accounts to assign this project to.</p>'
                    . '<ol><li>Open <strong>Users</strong>.</li><li>Create an account and select <strong>Project Manager</strong> as the role.</li><li>Return here to create and assign the project.</li></ol>'
                    . '<p><a class="button" href="' . e(url('users')) . '">Create Project Manager account</a> '
                    . '<a class="button secondary" href="' . e(url('projects')) . '">Back to projects</a></p></section>';
                render_page('Project Manager required', $content, $user, $message);
                exit;
            }
        }
        $managerField = has_permission($user, 'users.manage')
            ? '<label>Assign project manager<select name="project_manager_id" required><option value="">Select a manager</option>' . $managerOptions . '</select></label>'
            : '<p>New projects will be assigned to your account.</p>';
        $content = '<section class="card"><form class="grid-form" method="post" action="' . e(url('project_new')) . '" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">'
            . '<label>Project code<input name="project_code" maxlength="40" required placeholder="e.g. NVM-2026-001"></label>'
            . '<label>Project title<input name="title" maxlength="180" required></label>'
            . '<label>Department<input name="department" maxlength="150"></label><label>Location<input name="location" maxlength="180"></label>'
            . $managerField . '<label class="full-width">Description<textarea name="description" maxlength="20000" rows="5"></textarea></label>'
            . '<label class="full-width">Project photo or video<input type="file" name="project_media" accept=".jpg,.jpeg,.png,.mp4,.webm,image/jpeg,image/png,video/mp4,video/webm"></label>'
            . '<div class="media-preview full-width" data-media-preview hidden aria-live="polite"></div>'
            . '<p class="full-width muted">Optional photo or short video proof for this project. JPG, PNG, MP4, and WEBM up to 50 MB.</p>'
            . '<div class="form-actions"><button type="submit">Save project</button> <a class="button secondary" href="' . e(url('projects')) . '">Cancel</a></div></form></section>';
        render_page('Create project', $content, $user, $message);
        exit;
    }

    if ($page === 'audit') {
        require_permission($user, 'audit_logs.view');
        $logs = db()->query(
            'SELECT a.event_key, a.record_id, a.details, a.ip_address, a.created_at, u.full_name
             FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
             ORDER BY a.created_at DESC LIMIT 200'
        )->fetchAll();
        $rows = '';
        foreach ($logs as $log) {
            $rows .= '<tr><td>' . e($log['created_at']) . '</td><td>' . e($log['full_name'] ?? 'System/removed user') . '</td><td>' . e($log['event_key']) . '</td><td>' . e($log['record_id'] === null ? '' : (string) $log['record_id']) . '</td><td><code>' . e($log['details']) . '</code></td></tr>';
        }
        if ($rows === '') {
            $rows = '<tr><td colspan="5">No audit events have been recorded.</td></tr>';
        }
        $content = '<section class="card"><div class="table-wrap"><table><thead><tr><th>Time</th><th>User</th><th>Event</th><th>Record ID</th><th>Details</th></tr></thead><tbody>' . $rows . '</tbody></table></div></section>';
        render_page('Audit log', $content, $user, $message);
        exit;
    }

    http_response_code(404);
    render_page('Page not found', '<p>The page you requested does not exist.</p>', $user);
} catch (Throwable $exception) {
    error_log($exception->__toString());
    if ($exception instanceof PDOException) {
        http_response_code(500);
        $errorMessage = $config['debug'] ? $exception->getMessage() : 'A database error prevented the request from completing. Check the server log for details.';
    } elseif ($exception instanceof RuntimeException) {
        if (http_response_code() < 400) {
            http_response_code(400);
        }
        $errorMessage = $exception->getMessage();
    } else {
        http_response_code(500);
        $errorMessage = $config['debug'] ? $exception->getMessage() : 'An unexpected error prevented the request from completing.';
    }
    $content = '<section class="card error"><p>' . e($errorMessage) . '</p><p><a href="' . e(url($user ? 'dashboard' : 'login')) . '">Return to the application</a></p></section>';
    render_page('Unable to complete request', $content);
}
