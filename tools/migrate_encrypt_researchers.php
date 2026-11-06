<?php
declare(strict_types=1);

/**
 * Phase 6: one-off migration - encrypts the plaintext fake values that
 * Phase 4's sample data inserted directly into national_id_enc, phone_enc
 * and bank_account_enc (which were plaintext placeholders, not actually
 * encrypted, since encryption didn't exist yet at that point).
 *
 * Run ONCE from the command line, after generate_key.php:
 *     & "C:\xampp\php\php.exe" tools\migrate_encrypt_researchers.php
 *
 * Connects as dba_admin (needs UPDATE on researchers, which only the DBA
 * role has - matches the least-privilege design from Phase 2).
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

$select = $db->query('SELECT researcher_id, national_id_enc, phone_enc, bank_account_enc FROM researchers');
$update = $db->prepare('UPDATE researchers SET national_id_enc=?, phone_enc=?, bank_account_enc=? WHERE researcher_id=?');

$count = 0;
while ($row = $select->fetch_assoc()) {
    // Heuristic: if the stored bytes already look like our ciphertext format
    // (longer than any plausible plaintext and not valid UTF-8 text), skip it,
    // so running this script twice does not double-encrypt the same row.
    $looksEncrypted = strlen($row['national_id_enc']) > 60 || !mb_check_encoding($row['national_id_enc'], 'UTF-8');
    if ($looksEncrypted) {
        echo "researcher_id {$row['researcher_id']}: already encrypted, skipped.\n";
        continue;
    }

    $nid   = encrypt_value($row['national_id_enc'], $key);
    $phone = $row['phone_enc'] !== null ? encrypt_value($row['phone_enc'], $key) : null;
    $bank  = $row['bank_account_enc'] !== null ? encrypt_value($row['bank_account_enc'], $key) : null;

    $researcherId = $row['researcher_id'];
    $update->bind_param('sssi', $nid, $phone, $bank, $researcherId);
    $update->execute();

    echo "researcher_id {$row['researcher_id']}: encrypted.\n";
    $count++;
}

echo "\nDone. $count row(s) encrypted.\n";
$update->close();
$db->close();
