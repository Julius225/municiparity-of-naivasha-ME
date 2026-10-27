<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$envFile = $root . DIRECTORY_SEPARATOR . '.env';

if (is_file($envFile) && is_readable($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        throw new RuntimeException('Unable to read the application environment file.');
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }

        [$name, $value] = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);
        if ($name === '') {
            continue;
        }

        if (strlen($value) >= 2 && (($value[0] === '"' && $value[strlen($value) - 1] === '"') || ($value[0] === "'" && $value[strlen($value) - 1] === "'"))) {
            $value = substr($value, 1, -1);
        }

        if (getenv($name) === false) {
            putenv($name . '=' . $value);
            $_ENV[$name] = $value;
        }
    }
}

$debug = filter_var(getenv('APP_DEBUG') ?: 'false', FILTER_VALIDATE_BOOLEAN);
$setupKey = getenv('MUNI_SETUP_KEY') ?: '';
$appUrl = rtrim(getenv('APP_URL') ?: '', '/');
$mailFrom = getenv('MAIL_FROM') ?: '';
$environment = getenv('APP_ENV') ?: 'production';
$database = [
    'host' => getenv('DB_HOST') ?: '127.0.0.1',
    'port' => getenv('DB_PORT') ?: '3306',
    'name' => getenv('DB_NAME') ?: '',
    'user' => getenv('DB_USER') ?: '',
    'password' => getenv('DB_PASSWORD') ?: '',
];
$productionErrors = [];
if ($environment === 'production') {
    if ($debug) {
        $productionErrors[] = 'APP_DEBUG must be false.';
    }
    if ($database['name'] === '' || $database['user'] === '' || $database['password'] === '') {
        $productionErrors[] = 'Configure DB_NAME, DB_USER, and a non-empty DB_PASSWORD.';
    }
    if (strtolower($database['user']) === 'root') {
        $productionErrors[] = 'DB_USER must be a dedicated least-privilege account, not root.';
    }
    $appUrlParts = $appUrl !== '' ? parse_url($appUrl) : false;
    if (!is_array($appUrlParts) || ($appUrlParts['scheme'] ?? '') !== 'https' || empty($appUrlParts['host'])) {
        $productionErrors[] = 'APP_URL must be an absolute HTTPS URL.';
    }
    if (!filter_var($mailFrom, FILTER_VALIDATE_EMAIL)) {
        $productionErrors[] = 'MAIL_FROM must be a valid email address for password reset messages.';
    }
}

return [
    'root' => $root,
    'name' => getenv('APP_NAME') ?: 'Municipal Project Monitoring and Evaluation',
    'environment' => $environment,
    'debug' => $debug,
    'setup_key' => $setupKey,
    'setup_key_configured' => strlen($setupKey) >= 32 && $setupKey !== 'replace-with-a-long-random-secret',
    'app_url' => $appUrl,
    'mail_from' => $mailFrom,
    'password_reset_enabled' => filter_var($mailFrom, FILTER_VALIDATE_EMAIL) !== false && filter_var($appUrl, FILTER_VALIDATE_URL) !== false,
    'production_errors' => $productionErrors,
    'private_storage_path' => getenv('PRIVATE_STORAGE_PATH') ?: $root . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'private',
    'backup_path' => getenv('BACKUP_DIR') ?: $root . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'backups',
    'database' => $database,
];
