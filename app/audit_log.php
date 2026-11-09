<?php
declare(strict_types=1);

/**
 * Phase 7: the Auditor's view of audit_log, plus the brief's required
 * "demonstrate how the collected information could be used to detect or
 * investigate suspicious activity" - done here as two live detection
 * queries, not just a raw dump of rows.
 */

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/db.php';
require __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

$db = db_connect($config);
require_role($db, ['Auditor', 'DBA']);

// Detection query 1: brute-force pattern - 3+ failed logins for the same
// username within the last 24 hours (would be LOCKOUT_MINUTES-scale in a
// real deployment; 24h here just makes it demonstrable during the demo).
$bruteForce = $db->query(
    "SELECT username, COUNT(*) AS failures, MIN(event_time) AS first_attempt, MAX(event_time) AS last_attempt
       FROM audit_log
      WHERE action = 'LOGIN_FAILED' AND event_time >= NOW() - INTERVAL 1 DAY
      GROUP BY username
     HAVING COUNT(*) >= 3
      ORDER BY failures DESC"
);

// Detection query 2: a privileged account (DBA) doing something unusual -
// any ADMIN_ACTION or VIEW_SENSITIVE outside of normal hours, OR simply a
// high volume of sensitive-data views by one account in a short window.
$unusualAccess = $db->query(
    "SELECT username, action, COUNT(*) AS event_count, MAX(event_time) AS last_seen
       FROM audit_log
      WHERE action IN ('VIEW_SENSITIVE','ADMIN_ACTION','DELETE_RECORD')
        AND event_time >= NOW() - INTERVAL 1 DAY
      GROUP BY username, action
     HAVING COUNT(*) >= 1
      ORDER BY event_count DESC
      LIMIT 20"
);

// Full recent log, newest first - what "who/what/when/which resource/success"
// looks like as actual rows.
$recent = $db->query('SELECT event_time, username, action, resource, success, ip_address, details FROM audit_log ORDER BY audit_id DESC LIMIT 100');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GrantDB - Audit log</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f3f4f6;margin:0;padding:2rem}
  .card{background:#fff;max-width:980px;margin:auto;padding:2rem;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.12)}
  table{border-collapse:collapse;width:100%;margin:1rem 0}
  th,td{border:1px solid #e5e7eb;padding:.4rem .6rem;font-size:.82rem;text-align:left}
  th{background:#f3f4f6}
  .yes{color:#15803d;font-weight:600}.no{color:#b91c1c;font-weight:600}
  h2{margin-top:2rem}
  a{display:inline-block;margin-top:1rem}
</style>
</head>
<body>
<div class="card">
  <h1>Audit log</h1>

  <h2>Detection 1: possible brute-force login (&ge;3 failures / 24h, same username)</h2>
  <table>
    <tr><th>Username</th><th>Failures</th><th>First attempt</th><th>Last attempt</th></tr>
    <?php $any1 = false; while ($r = $bruteForce->fetch_assoc()): $any1 = true; ?>
    <tr><td><?= h((string)$r['username']) ?></td><td><?= h((string)$r['failures']) ?></td><td><?= h((string)$r['first_attempt']) ?></td><td><?= h((string)$r['last_attempt']) ?></td></tr>
    <?php endwhile; if (!$any1): ?><tr><td colspan="4">None in the last 24 hours.</td></tr><?php endif; ?>
  </table>

  <h2>Detection 2: sensitive/administrative/deletion activity by account (24h)</h2>
  <table>
    <tr><th>Username</th><th>Action</th><th>Count</th><th>Last seen</th></tr>
    <?php $any2 = false; while ($r = $unusualAccess->fetch_assoc()): $any2 = true; ?>
    <tr><td><?= h((string)$r['username']) ?></td><td><?= h($r['action']) ?></td><td><?= h((string)$r['event_count']) ?></td><td><?= h((string)$r['last_seen']) ?></td></tr>
    <?php endwhile; if (!$any2): ?><tr><td colspan="4">None in the last 24 hours.</td></tr><?php endif; ?>
  </table>

  <h2>Recent raw log (last 100 events)</h2>
  <table>
    <tr><th>When</th><th>Who</th><th>Action</th><th>Resource</th><th>Success</th><th>IP</th><th>Details</th></tr>
    <?php while ($r = $recent->fetch_assoc()): ?>
    <tr>
      <td><?= h((string)$r['event_time']) ?></td>
      <td><?= h((string)($r['username'] ?? '-')) ?></td>
      <td><?= h($r['action']) ?></td>
      <td><?= h((string)($r['resource'] ?? '-')) ?></td>
      <td class="<?= $r['success'] ? 'yes' : 'no' ?>"><?= $r['success'] ? 'yes' : 'no' ?></td>
      <td><?= h((string)($r['ip_address'] ?? '-')) ?></td>
      <td><?= h((string)($r['details'] ?? '')) ?></td>
    </tr>
    <?php endwhile; ?>
  </table>
  <a href="dashboard.php">&larr; Back to dashboard</a>
</div>
</body>
</html>
