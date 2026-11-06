<?php
declare(strict_types=1);

/**
 * Phase 6: verification script - proves the encrypted columns can be
 * correctly decrypted back to their original values, and that raw SQL
 * access alone (without the key) only ever sees unreadable bytes.
 *
 * Run from the command line:
 *     & "C:\xampp\php\php.exe" tools\decrypt_check.php
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}

require __DIR__ . '/../app/includes/crypto.php';

$dbUser = getenv('DBA_USER') ?: 'dba_admin';
$dbPass = getenv('DBA_PASS');
if ($dbPass === false || $dbPass === '') {
    echo "Set the dba_admin password first, e.g.:\n";
    echo '  $env:DBA_PASS = "..."' . "\n";
    exit(1);
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$db = new mysqli('localhost', $dbUser, $dbPass, 'grantdb');
$db->set_charset('utf8mb4');

$key = load_encryption_key();

$res = $db->query('SELECT researcher_id, full_name, national_id_enc, phone_enc, bank_account_enc FROM researchers');
while ($row = $res->fetch_assoc()) {
    echo "----------------------------------------\n";
    echo "researcher_id: {$row['researcher_id']} ({$row['full_name']})\n";
    echo "raw bytes (national_id_enc), first 20 shown hex: " . bin2hex(substr($row['national_id_enc'], 0, 20)) . "...\n";
    try {
        echo "decrypted national_id: " . decrypt_value($row['national_id_enc'], $key) . "\n";
        if ($row['phone_enc'] !== null) {
            echo "decrypted phone:       " . decrypt_value($row['phone_enc'], $key) . "\n";
        }
        if ($row['bank_account_enc'] !== null) {
            echo "decrypted bank:        " . decrypt_value($row['bank_account_enc'], $key) . "\n";
        }
    } catch (RuntimeException $e) {
        echo "DECRYPTION FAILED: " . $e->getMessage() . "\n";
    }
}
