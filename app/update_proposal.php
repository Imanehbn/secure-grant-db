<?php
declare(strict_types=1);

/**
 * Phase 7: "Record modification" audit event.
 *
 * A minimal GrantsOfficer action: change a proposal's status
 * (e.g. Submitted -> UnderReview -> Approved/Rejected). Deliberately simple
 * UI (per the brief: "the user interface does not need to be sophisticated")
 * - the point is the audit trail around the UPDATE, not the workflow.
 */

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/db.php';
require __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

$db = db_connect($config);
require_role($db, ['GrantsOfficer', 'DBA']);

$allowedStatuses = ['Submitted', 'Under Review', 'Approved', 'Rejected'];
$error = null;
$done  = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_check((string)($_POST['csrf'] ?? ''))) {
        $error = 'Invalid request (CSRF check failed). Please try again.';
    } else {
        $proposalId = (int)($_POST['proposal_id'] ?? 0);
        $newStatus  = (string)($_POST['status'] ?? '');

        if ($proposalId <= 0 || !in_array($newStatus, $allowedStatuses, true)) {
            $error = 'Please choose a valid proposal and status.';
        } else {
            $stmt = $db->prepare('UPDATE proposals SET status = ? WHERE proposal_id = ?');
            $stmt->bind_param('si', $newStatus, $proposalId);
            $stmt->execute();
            $affected = $stmt->affected_rows;
            $stmt->close();

            // Logged whether or not a row actually changed, so a no-op attempt
            // (wrong ID, already in that status) is still traceable.
            audit($db, (int)$_SESSION['user_id'], (string)$_SESSION['username'],
                  'UPDATE_RECORD', 'proposals:' . $proposalId, $affected > 0,
                  'set status = ' . $newStatus);

            $done = $affected > 0;
            if (!$done) {
                $error = 'No proposal with that ID was found (nothing changed).';
            }
        }
    }
}

$proposals = $db->query('SELECT proposal_id, title, status FROM proposals ORDER BY proposal_id');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GrantDB - Update proposal status</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f3f4f6;margin:0;padding:2rem}
  .card{background:#fff;max-width:600px;margin:auto;padding:2rem;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.12)}
  table{border-collapse:collapse;width:100%;margin:1rem 0}
  th,td{border:1px solid #e5e7eb;padding:.4rem .6rem;font-size:.88rem;text-align:left}
  input,select,button{padding:.5rem;margin:.3rem 0;width:100%;box-sizing:border-box}
  button{background:#991b1b;color:#fff;border:0;border-radius:6px;cursor:pointer}
  .ok{color:#15803d}.err{color:#b91c1c}
  a{display:inline-block;margin-top:1rem}
</style>
</head>
<body>
<div class="card">
  <h1>Update proposal status</h1>
  <?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
  <?php if ($done): ?><p class="ok">Status updated. This change was recorded in audit_log.</p><?php endif; ?>

  <table>
    <tr><th>ID</th><th>Title</th><th>Status</th></tr>
    <?php while ($p = $proposals->fetch_assoc()): ?>
    <tr><td><?= h((string)$p['proposal_id']) ?></td><td><?= h($p['title']) ?></td><td><?= h($p['status']) ?></td></tr>
    <?php endwhile; ?>
  </table>

  <form method="post">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
    <label>Proposal ID</label>
    <input type="number" name="proposal_id" required>
    <label>New status</label>
    <select name="status" required>
      <?php foreach ($allowedStatuses as $s): ?><option value="<?= h($s) ?>"><?= h($s) ?></option><?php endforeach; ?>
    </select>
    <button type="submit">Save</button>
  </form>
  <a href="dashboard.php">&larr; Back to dashboard</a>
</div>
</body>
</html>
