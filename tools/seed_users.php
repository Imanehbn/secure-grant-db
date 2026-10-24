<?php
declare(strict_types=1);

/**
 * One-off lab script: creates one application login per role in grantdb.users.
 * Run from the project folder, in a terminal (NOT from the browser):
 *
 *     & "C:\xampp\php\php.exe" tools\seed_users.php
 *
 * It connects as root (the XAMPP default has no password). If you have already
 * set a root password (Phase 9), set it first:   $env:SEED_DB_PASS = "..."
 *
 * Passwords are generated randomly, hashed with password_hash (bcrypt), and the
 * plain values are written to a file OUTSIDE the repository.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}

$dbUser = getenv('SEED_DB_USER') ?: 'root';
$dbPass = getenv('SEED_DB_PASS') ?: '';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$db = new mysqli('localhost', $dbUser, $dbPass, 'grantdb');
$db->set_charset('utf8mb4');

// username => [role_id, email]
$accounts = [
    'app_dba'      => [1, 'dba@example.test'],
    'app_officer'  => [2, 'officer@example.test'],
    'app_pi'       => [3, 'pi@example.test'],
    'app_reviewer' => [4, 'reviewer@example.test'],
    'app_finance'  => [5, 'finance@example.test'],
    'app_auditor'  => [6, 'auditor@example.test'],
];

function random_password(int $length = 16): string
{
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; // no look-alikes
    $out = '';
    for ($i = 0; $i < $length; $i++) {
        $out .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $out;
}

$stmt = $db->prepare(
    'INSERT INTO users (username, password_hash, role_id, email)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash),
                             failed_attempts = 0, locked_until = NULL, is_active = 1'
);

$lines = [];
foreach ($accounts as $username => [$roleId, $email]) {
    $plain = random_password();
    $hash  = password_hash($plain, PASSWORD_DEFAULT);
    $stmt->bind_param('ssis', $username, $hash, $roleId, $email);
    $stmt->execute();
    $lines[] = $username . ' : ' . $plain;
    echo "created/updated: $username\n";
}
$stmt->close();
$db->close();

$home = getenv('USERPROFILE') ?: getenv('HOME') ?: '.';
$file = $home . DIRECTORY_SEPARATOR . 'Documents' . DIRECTORY_SEPARATOR . 'app-passwords.txt';
file_put_contents($file, implode(PHP_EOL, $lines) . PHP_EOL);

echo "\nPasswords saved OUTSIDE the repo in:\n  $file\n";
echo "Do not commit it and do not paste it anywhere.\n";
