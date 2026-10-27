<?php
declare(strict_types=1);

$config = require dirname(__DIR__) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'app.php';

error_reporting(E_ALL);
ini_set('display_errors', $config['debug'] ? '1' : '0');
ini_set('log_errors', '1');

$basePath = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
$basePath = $basePath === '' ? '' : $basePath;

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'httponly' => true,
        'secure' => $config['environment'] === 'production' || (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'samesite' => 'Lax',
        'path' => $basePath !== '' ? $basePath : '/',
    ]);
    session_start();
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store');

function db(): PDO
{
    global $config;
    static $pdo;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $database = $config['database'];
    if ($database['name'] === '' || $database['user'] === '') {
        throw new RuntimeException('Database settings are missing. Configure DB_NAME and DB_USER in the root .env file.');
    }

    $dsn = sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        $database['host'],
        $database['port'],
        $database['name']
    );
    $pdo = new PDO($dsn, $database['user'], $database['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $pdo;
}

function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function url(string $page, array $parameters = []): string
{
    global $basePath;
    $query = http_build_query(['page' => $page] + $parameters);
    return $basePath . '/index.php?' . $query;
}

function redirect(string $page, array $parameters = []): void
{
    header('Location: ' . url($page, $parameters), true, 303);
    exit;
}

function send_password_reset_email(string $email, string $token): bool
{
    global $config;

    if (!$config['password_reset_enabled']) {
        throw new RuntimeException('Password reset is unavailable until APP_URL and MAIL_FROM are configured in the root .env file.');
    }

    $resetUrl = $config['app_url'] . '/index.php?' . http_build_query([
        'page' => 'reset_password',
        'token' => $token,
    ]);
    $subject = 'Password reset instructions';
    $body = "A password reset was requested for your MunicipalFlow account.\r\n\r\n"
        . "Use this link within 60 minutes to choose a new password:\r\n"
        . $resetUrl . "\r\n\r\n"
        . "If you did not request this, you can ignore this email.";
    $headers = [
        'From: ' . $config['mail_from'],
        'Content-Type: text/plain; charset=UTF-8',
        'X-Auto-Response-Suppress: All',
    ];

    return mail($email, $subject, $body, implode("\r\n", $headers));
}

function csrf_token(): string
{
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(): void
{
    $submitted = $_POST['_csrf'] ?? '';
    if (!is_string($submitted) || !hash_equals(csrf_token(), $submitted)) {
        http_response_code(400);
        throw new RuntimeException('Your form session expired. Reload the page and try again.');
    }
}

function current_user(): ?array
{
    if (!isset($_SESSION['user_id'])) {
        return null;
    }

    $lastActivity = (int) ($_SESSION['last_activity'] ?? 0);
    if ($lastActivity > 0 && time() - $lastActivity > 1800) {
        logout_user();
        return null;
    }

    $statement = db()->prepare(
        'SELECT u.id, u.full_name, u.email, u.role_id, r.name AS role_name
         FROM users u
         INNER JOIN roles r ON r.id = u.role_id
         WHERE u.id = :id AND u.is_active = 1'
    );
    $statement->execute(['id' => (int) $_SESSION['user_id']]);
    $user = $statement->fetch();

    if (!$user) {
        logout_user();
        return null;
    }

    $_SESSION['last_activity'] = time();
    return $user;
}

function logout_user(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $parameters = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $parameters['path'],
            'domain' => $parameters['domain'],
            'secure' => $parameters['secure'],
            'httponly' => $parameters['httponly'],
            'samesite' => $parameters['samesite'] ?? 'Lax',
        ]);
    }
    session_destroy();
}

function require_login(): array
{
    $user = current_user();
    if (!$user) {
        redirect('login');
    }
    return $user;
}

function has_permission(array $user, string $permission): bool
{
    static $cache = [];
    $key = (int) $user['id'] . ':' . $permission;
    if (!array_key_exists($key, $cache)) {
        $statement = db()->prepare(
            'SELECT 1
             FROM role_permissions rp
             INNER JOIN permissions p ON p.id = rp.permission_id
             INNER JOIN users u ON u.role_id = rp.role_id
             WHERE u.id = :user_id AND p.permission_key = :permission_key
             LIMIT 1'
        );
        $statement->execute([
            'user_id' => (int) $user['id'],
            'permission_key' => $permission,
        ]);
        $cache[$key] = (bool) $statement->fetchColumn();
    }
    return $cache[$key];
}

function require_permission(array $user, string $permission): void
{
    if (!has_permission($user, $permission)) {
        http_response_code(403);
        throw new RuntimeException('You do not have permission to perform this action.');
    }
}

function audit(string $event, ?int $recordId = null, array $details = []): void
{
    $statement = db()->prepare(
        'INSERT INTO audit_logs (user_id, event_key, record_id, details, ip_address, created_at)
         VALUES (:user_id, :event_key, :record_id, :details, :ip_address, NOW())'
    );
    $statement->execute([
        'user_id' => isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null,
        'event_key' => $event,
        'record_id' => $recordId,
        'details' => json_encode($details, JSON_THROW_ON_ERROR),
        'ip_address' => substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45),
    ]);
}

function private_storage_path(): string
{
    global $config;

    $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, (string) $config['private_storage_path']);
    $isAbsolute = DIRECTORY_SEPARATOR === '\\'
        ? preg_match('/^(?:[A-Za-z]:\\\\|\\\\\\\\)/', $path) === 1
        : str_starts_with($path, DIRECTORY_SEPARATOR);
    if (!$isAbsolute) {
        $path = $config['root'] . DIRECTORY_SEPARATOR . $path;
    }

    $drive = '';
    if (preg_match('/^([A-Za-z]:)/', $path, $matches) === 1) {
        $drive = $matches[1];
        $path = substr($path, 2);
    }
    $rooted = str_starts_with($path, DIRECTORY_SEPARATOR);
    $segments = [];
    foreach (explode(DIRECTORY_SEPARATOR, $path) as $segment) {
        if ($segment === '' || $segment === '.') {
            continue;
        }
        if ($segment === '..') {
            array_pop($segments);
            continue;
        }
        $segments[] = $segment;
    }
    $normalized = $drive . ($rooted ? DIRECTORY_SEPARATOR : '') . implode(DIRECTORY_SEPARATOR, $segments);

    $suffix = [];
    $probe = $normalized;
    while (realpath($probe) === false) {
        $parent = dirname($probe);
        if ($parent === $probe) {
            throw new RuntimeException('Unable to resolve the private storage directory.');
        }
        array_unshift($suffix, basename($probe));
        $probe = $parent;
    }
    $resolved = realpath($probe);
    if ($resolved === false) {
        throw new RuntimeException('Unable to resolve the private storage directory.');
    }
    if ($suffix !== []) {
        $resolved .= DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $suffix);
    }

    $publicRoot = realpath($config['root'] . DIRECTORY_SEPARATOR . 'public');
    if ($publicRoot === false) {
        throw new RuntimeException('Unable to resolve the public web directory.');
    }
    $publicRoot = rtrim($publicRoot, DIRECTORY_SEPARATOR);
    $resolved = rtrim($resolved, DIRECTORY_SEPARATOR);
    $publicPrefix = $publicRoot . DIRECTORY_SEPARATOR;
    $caseInsensitive = DIRECTORY_SEPARATOR === '\\';
    $comparisonPath = $caseInsensitive ? strtolower($resolved) : $resolved;
    $comparisonPublic = $caseInsensitive ? strtolower($publicRoot) : $publicRoot;
    $comparisonPrefix = $caseInsensitive ? strtolower($publicPrefix) : $publicPrefix;
    if ($comparisonPath === $comparisonPublic || str_starts_with($comparisonPath, $comparisonPrefix)) {
        throw new RuntimeException('Private storage must be outside the public web directory.');
    }

    return $resolved;
}

function is_first_setup_required(): bool
{
    $setupState = db()->query('SELECT setup_completed FROM installation_state WHERE id = 1')->fetchColumn();
    if ($setupState === false || (int) $setupState !== 0) {
        return false;
    }
    $userCount = db()->query('SELECT COUNT(*) FROM users')->fetchColumn();
    return (int) $userCount === 0;
}

function render_page(string $title, string $content, ?array $user = null, ?string $message = null): void
{
    global $config, $page;
    $token = e(csrf_token());
    $brand = e($config['name']);
    $safeTitle = e($title);
    $flash = $message !== null && $message !== '' ? '<div class="notice">' . e($message) . '</div>' : '';
    $navigation = '';
    $topbar = '';
    $notifications = '';
    $profile = '';

    if ($user) {
        $links = [
            ['page' => 'dashboard', 'label' => 'Dashboard', 'icon' => 'D'],
        ];
        if (has_permission($user, 'projects.view')) {
            $links[] = ['page' => 'projects', 'label' => 'All projects', 'icon' => 'P'];
        }
        if (has_permission($user, 'progress_reports.submit') || has_permission($user, 'progress_reports.view_all')) {
            $links[] = ['page' => 'progress_reports', 'label' => 'Progress reports', 'icon' => 'PR'];
        }
        if (has_permission($user, 'finance.view')) {
            $links[] = ['page' => 'finance', 'label' => 'Budgets & expenditure', 'icon' => 'F'];
        }
        if (has_permission($user, 'procurement.view')) {
            $links[] = ['page' => 'procurement', 'label' => 'Procurement', 'icon' => 'PR'];
        }
        if (has_permission($user, 'users.manage')) {
            $links[] = ['page' => 'users', 'label' => 'Users & access', 'icon' => 'U'];
        }
        if (has_permission($user, 'audit_logs.view')) {
            $links[] = ['page' => 'audit', 'label' => 'Audit log', 'icon' => 'A'];
        }
        $navigation = '';
        foreach ($links as $link) {
            $active = $page === $link['page'] || ($link['page'] === 'projects' && in_array($page, ['project', 'project_edit', 'project_new'], true));
            $navigation .= '<a class="sidebar-link' . ($active ? ' active' : '') . '" href="' . e(url($link['page'])) . '"'
                . ($active ? ' aria-current="page"' : '') . '><span class="nav-icon" aria-hidden="true">' . e($link['icon']) . '</span><span>' . e($link['label']) . '</span>';
            if ($link['page'] === 'progress_reports' && has_permission($user, 'progress_reports.review')) {
                $pending = (int) db()->query(
                    "SELECT COUNT(*) FROM project_progress_reports WHERE review_status = 'submitted'"
                )->fetchColumn();
                if ($pending > 0) {
                    $navigation .= '<span class="nav-count">' . $pending . '</span>';
                }
            }
            $navigation .= '</a>';
        }

        $search = has_permission($user, 'projects.view')
            ? '<form class="global-search" method="get" action="' . e(url('projects')) . '"><input type="hidden" name="page" value="projects"><label class="visually-hidden" for="global-search">Search projects</label><span aria-hidden="true">⌕</span><input id="global-search" type="search" name="q" maxlength="100" placeholder="Search projects..." value="' . e((string) ($page === 'projects' ? ($_GET['q'] ?? '') : '')) . '"></form>'
            : '';
        if (has_permission($user, 'progress_reports.view_all')) {
            $pendingNotifications = (int) db()->query(
                "SELECT COUNT(*) FROM project_progress_reports WHERE review_status = 'submitted'"
            )->fetchColumn();
            $notifications = '<a class="notification-link" href="' . e(url('progress_reports')) . '" aria-label="' . e($pendingNotifications . ' progress reports awaiting review') . '"><span aria-hidden="true">!</span>'
                . ($pendingNotifications > 0 ? '<span class="notification-count">' . $pendingNotifications . '</span>' : '') . '</a>';
        }
        $nameParts = preg_split('/\s+/', trim((string) $user['full_name'])) ?: [];
        $initials = strtoupper(substr($nameParts[0] ?? '', 0, 1) . (count($nameParts) > 1 ? substr($nameParts[count($nameParts) - 1], 0, 1) : ''));
        $roleLabel = ucwords(str_replace('_', ' ', (string) $user['role_name']));
        $profile = '<div class="profile-summary"><span class="avatar" aria-hidden="true">' . e($initials) . '</span><span class="profile-copy"><strong>' . e($user['full_name']) . '</strong><small>' . e($roleLabel) . '</small></span></div>'
            . '<form method="post" action="' . e(url('logout')) . '"><input type="hidden" name="_csrf" value="' . $token . '"><button class="logout-button" type="submit">Log out</button></form>';
        $topbar = '<header class="topbar"><button class="sidebar-toggle" type="button" aria-label="Collapse sidebar" aria-expanded="true">☰</button>' . $search . '<div class="topbar-actions">' . $notifications
            . '<span class="topbar-date">' . e(date('D, j M Y')) . '</span></div></header>';
    }

    require $config['root'] . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR
        . 'views' . DIRECTORY_SEPARATOR . 'layouts' . DIRECTORY_SEPARATOR . 'main.php';
}

function role_options(?int $selected = null): string
{
    $roles = db()->query('SELECT id, name, display_name FROM roles ORDER BY id')->fetchAll();
    $html = $selected === null ? '<option value="" disabled selected>Select a role</option>' : '';
    foreach ($roles as $role) {
        $isSelected = $selected === (int) $role['id'] ? ' selected' : '';
        $html .= '<option value="' . (int) $role['id'] . '"' . $isSelected . '>' . e($role['display_name']) . '</option>';
    }
    return $html;
}
