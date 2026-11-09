<?php
declare(strict_types=1);

/**
 * Phase 7: "Record deletion" audit event.
 *
 * Only a Draft proposal (never submitted) may be deleted - mirrors the
 * real-world rule that you don't let people destroy records that are
 * already part of the official review trail. The attempt is logged either
 * way, including a BLOCKED case, which is itself useful audit evidence
 * ("someone tried to delete a non-draft proposal").
 */

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/db.php';
require __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

$db = db_connect($config);
require_role($db, ['GrantsOfficer', 'DBA']);

$error = null;
$done  = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_check((string)($_POST['csrf'] ?? ''))) {
        $error = 'Invalid request (CSRF check failed). Please try again.';
    } else {
        $proposalId = (int)($_POST['proposal_id'] ?? 0);

        $chk = $db->prepare('SELECT status FROM proposals WHERE proposal_id = ?');
        $chk->bind_param('i', $proposalId);
        $chk->execute();
        $row = $chk->get_result()->fetch_assoc();
        $chk->close();

        if (!$row) {
            $error = 'No proposal with that ID.';
        } elseif ($row['status'] !== 'Draft') {
            // Blocked on purpose: an audit trail that only records SUCCESSFUL
            // deletions would miss exactly the kind of attempt an investigator
            // (Phase 10) would care most about.
            audit($db, (int)$_SESSION['user_id'], (string)$_SESSION['username'],
                  'DELETE_RECORD', 'proposals:' . $proposalId, false,
                  'blocked: status is ' . $row['status'] . ', only Draft may be deleted');
            $error = 'That proposal is not a Draft, so it cannot be deleted (this attempt was logged).';
        } else {
            $del = $db->prepare('DELETE FROM proposals WHERE proposal_id = ? AND status = \'Draft\'');
            $del->bind_param('i', $proposalId);
            $del->execute();
            $affected = $del->affected_rows;
            $del->close();

            audit($db, (int)$_SESSION['user_id'], (string)$_SESSION['username'],
                  'DELETE_RECORD', 'proposals:' . $proposalId, $affected > 0, null);

            $done = $affected > 0;
        }
    }
}

$proposals = $db->query("SELECT proposal_id, title, status FROM proposals WHERE status = 'Draft' ORDER BY proposal_id");
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GrantDB - Delete draft proposal</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f3f4f6;margin:0;padding:2rem}
  .card{background:#fff;max-width:600px;margin:auto;padding:2rem;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.12)}
  table{border-collapse:collapse;width:100%;margin:1rem 0}
  th,td{border:1px solid #e5e7eb;padding:.4rem .6rem;font-size:.88rem;text-align:left}
  input,button{padding:.5rem;margin:.3rem 0;width:100%;box-sizing:border-box}
  button{background:#991b1b;color:#fff;border:0;border-radius:6px;cursor:pointer}
  .ok{color:#15803d}.err{color:#b91c1c}
  a{display:inline-block;margin-top:1rem}
</style>
</head>
<body>
<div class="card">
  <h1>Delete a Draft proposal</h1>
  <?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
  <?php if ($done): ?><p class="ok">Proposal deleted. This was recorded in audit_log.</p><?php endif; ?>

  <table>
    <tr><th>ID</th><th>Title</th><th>Status</th></tr>
    <?php while ($p = $proposals->fetch_assoc()): ?>
    <tr><td><?= h((string)$p['proposal_id']) ?></td><td><?= h($p['title']) ?></td><td><?= h($p['status']) ?></td></tr>
    <?php endwhile; ?>
  </table>

  <form method="post" onsubmit="return confirm('Delete this proposal permanently?');">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
    <label>Proposal ID to delete</label>
    <input type="number" name="proposal_id" required>
    <button type="submit">Delete</button>
  </form>
  <a href="dashboard.php">&larr; Back to dashboard</a>
</div>
</body>
</html>
