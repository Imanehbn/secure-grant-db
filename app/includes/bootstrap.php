<?php
declare(strict_types=1);

// Errors are logged, never shown to the visitor (secure error handling).
ini_set('display_errors', '0');
ini_set('log_errors', '1');

$config = require __DIR__ . '/../config.php';

const MAX_FAILED_ATTEMPTS  = 5;    // failed logins before lockout
const LOCKOUT_MINUTES      = 15;   // lockout duration
const IDLE_TIMEOUT_SECONDS = 900;  // 15 minutes of inactivity ends the session

function send_security_headers(): void
{
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
    header('Cache-Control: no-store, no-cache, must-revalidate');
}

function start_secure_session(): void
{
    ini_set('session.use_strict_mode', '1');   // refuse session IDs the server did not create
    ini_set('session.use_only_cookies', '1');  // never accept the ID in the URL
    session_name('GRANTSESSID');
    session_set_cookie_params([
        'lifetime' => 0,                        // cookie dies when the browser closes
        'path'     => '/',
        'secure'   => !empty($_SERVER['HTTPS']), // true once HTTPS is enabled
        'httponly' => true,                     // JavaScript cannot read the cookie
        'samesite' => 'Strict',                 // not sent on cross-site requests
    ]);
    session_start();

    if (isset($_SESSION['user_id'])) {
        $idle = time() - (int)($_SESSION['last_activity'] ?? 0);
        if ($idle > IDLE_TIMEOUT_SECONDS) {
            destroy_session();
            session_start();
        } else {
            $_SESSION['last_activity'] = time();
        }
    }
}

function destroy_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 3600,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => 'Strict',
        ]);
    }
    session_destroy();
}

function require_login(): void
{
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_check(string $token): bool
{
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

// Escape every value printed into HTML (prevents XSS).
function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Only REMOTE_ADDR is trusted; X-Forwarded-For can be forged by the client.
function client_ip(): string
{
    return substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
}

// Spend roughly the same time as a real password check, so response time
// does not reveal whether a username exists.
function burn_cpu(string $password): void
{
    password_hash($password, PASSWORD_DEFAULT);
}

// Who / what / when / which resource / success? (when = column default)
function audit(mysqli $db, ?int $userId, ?string $username, string $action,
               string $resource, bool $success, ?string $details = null): void
{
    $clean = static fn(?string $s, int $max): ?string =>
        $s === null ? null : substr((string)preg_replace('/[\x00-\x1F\x7F]/', '', $s), 0, $max);

    $username = $clean($username, 50);
    $details  = $clean($details, 500);
    $ip       = client_ip();
    $ok       = $success ? 1 : 0;

    $stmt = $db->prepare(
        'INSERT INTO audit_log (user_id, username, action, resource, success, ip_address, details)
         VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    $stmt->bind_param('isssiss', $userId, $username, $action, $resource, $ok, $ip, $details);
    $stmt->execute();
    $stmt->close();
}
