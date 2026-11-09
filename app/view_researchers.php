<?php
declare(strict_types=1);

/**
 * Phase 7: "Access to sensitive information" audit event.
 *
 * Shows the decrypted Restricted-classification fields from Phase 6
 * (national_id, phone, bank_account) to the roles that are actually
 * allowed to see them: PI (their own data would be the real design,
 * DBA/FinanceOfficer/Auditor for this demo), and logs EVERY view,
 * whether or not anything was decrypted, so the log reflects reality.
 */

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/db.php';
require __DIR__ . '/includes/auth.php';
require __DIR__ . '/includes/crypto.php';

send_security_headers();
start_secure_session();

$db = db_connect($config);
require_role($db, ['DBA', 'FinanceOfficer', 'Auditor']);

$rows = [];
$result = $db->query('SELECT researcher_id, full_name, national_id_enc, phone_enc, bank_account_enc FROM researchers');
while ($row = $result->fetch_assoc()) {
    $rid = (int)$row['researcher_id'];
    try {
        $key = load_encryption_key();
        $row['national_id'] = decrypt_value($row['national_id_enc'], $key);
        $row['phone']       = $row['phone_enc'] !== null ? decrypt_value($row['phone_enc'], $key) : null;
        $row['bank']        = $row['bank_account_enc'] !== null ? decrypt_value($row['bank_account_enc'], $key) : null;

        // One audit row PER researcher record actually viewed: the brief asks
        // "which resource was affected", so the resource identifies the exact row.
        audit($db, (int)$_SESSION['user_id'], (string)$_SESSION['username'],
              'VIEW_SENSITIVE', 'researchers:' . $rid, true, null);
    } catch (RuntimeException $e) {
        $row['national_id'] = $row['phone'] = $row['bank'] = '[decryption failed]';
        audit($db, (int)$_SESSION['user_id'], (string)$_SESSION['username'],
              'VIEW_SENSITIVE', 'researchers:' . $rid, false, $e->getMessage());
    }
    $rows[] = $row;
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GrantDB - Researcher sensitive data</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f3f4f6;margin:0;padding:2rem}
  .card{background:#fff;max-width:780px;margin:auto;padding:2rem;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.12)}
  table{border-collapse:collapse;width:100%;margin-top:1rem}
  th,td{border:1px solid #e5e7eb;padding:.5rem .7rem;text-align:left;font-size:.9rem}
  th{background:#f3f4f6}
  a{display:inline-block;margin-top:1.5rem}
</style>
</head>
<body>
<div class="card">
  <h1>Researcher sensitive data (Restricted)</h1>
  <p>Every row shown here was just written to <code>audit_log</code> as a <code>VIEW_SENSITIVE</code> event.</p>
  <table>
    <tr><th>ID</th><th>Name</th><th>National ID</th><th>Phone</th><th>Bank account</th></tr>
    <?php foreach ($rows as $r): ?>
    <tr>
      <td><?= h((string)$r['researcher_id']) ?></td>
      <td><?= h((string)$r['full_name']) ?></td>
      <td><?= h((string)$r['national_id']) ?></td>
      <td><?= h((string)($r['phone'] ?? '')) ?></td>
      <td><?= h((string)($r['bank'] ?? '')) ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
  <a href="dashboard.php">&larr; Back to dashboard</a>
</div>
</body>
</html>
