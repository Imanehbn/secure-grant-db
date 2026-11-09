<?php
declare(strict_types=1);

/**
 * Phase 7: "Administrative action" audit event.
 *
 * DBA-only: lock, unlock, activate or deactivate a user account. These are
 * exactly the kind of privileged operations Phase 10's incident investigation
 * will later ask "did a privileged account do something unusual?" about.
 */

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/db.php';
require __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

$db = db_connect($config);
require_role($db, ['DBA']);

$error = null;
$done  = null;
$allowedActions = ['activate', 'deactivate', 'unlock'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_check((string)($_POST['csrf'] ?? ''))) {
        $error = 'Invalid request (CSRF check failed). Please try again.';
    } else {
        $targetId = (int)($_POST['user_id'] ?? 0);
        $action   = (string)($_POST['action'] ?? '');

        if ($targetId <= 0 || !in_array($action, $allowedActions, true)) {
            $error = 'Please choose a valid user and action.';
        } else {
            switch ($action) {
                case 'activate':
                    $stmt = $db->prepare('UPDATE users SET is_active = 1 WHERE user_id = ?');
                    $stmt->bind_param('i', $targetId);
                    break;
                case 'deactivate':
                    $stmt = $db->prepare('UPDATE users SET is_active = 0 WHERE user_id = ?');
                    $stmt->bind_param('i', $targetId);
                    break;
                default: // unlock
                    $stmt = $db->prepare('UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE user_id = ?');
                    $stmt->bind_param('i', $targetId);
            }
            $stmt->execute();
            $affected = $stmt->affected_rows;
            $stmt->close();

            audit($db, (int)$_SESSION['user_id'], (string)$_SESSION['username'],
                  'ADMIN_ACTION', 'users:' . $targetId, $affected > 0,
                  'action=' . $action);

            $done = $affected > 0;
            if (!$done) {
                $error = 'No matching user, or the account was already in that state.';
            }
        }
    }
}

$users = $db->query(
    'SELECT u.user_id, u.username, r.role_name, u.is_active,
            (u.locked_until IS NOT NULL AND u.locked_until > NOW()) AS is_locked
       FROM users u JOIN app_roles r ON r.role_id = u.role_id
      ORDER BY u.user_id'
);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GrantDB - Administer user accounts</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f3f4f6;margin:0;padding:2rem}
  .card{background:#fff;max-width:720px;margin:auto;padding:2rem;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.12)}
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
  <h1>Administer user accounts (DBA)</h1>
  <?php if ($error): ?><p class="err"><?= h($error) ?></p><?php endif; ?>
  <?php if ($done): ?><p class="ok">Account updated. This administrative action was recorded in audit_log.</p><?php endif; ?>

  <table>
    <tr><th>ID</th><th>Username</th><th>Role</th><th>Active</th><th>Locked</th></tr>
    <?php while ($u = $users->fetch_assoc()): ?>
    <tr>
      <td><?= h((string)$u['user_id']) ?></td>
      <td><?= h($u['username']) ?></td>
      <td><?= h($u['role_name']) ?></td>
      <td><?= $u['is_active'] ? 'yes' : 'no' ?></td>
      <td><?= $u['is_locked'] ? 'yes' : 'no' ?></td>
    </tr>
    <?php endwhile; ?>
  </table>

  <form method="post">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
    <label>User ID</label>
    <input type="number" name="user_id" required>
    <label>Action</label>
    <select name="action" required>
      <option value="activate">Activate</option>
      <option value="deactivate">Deactivate</option>
      <option value="unlock">Unlock (clear lockout)</option>
    </select>
    <button type="submit">Apply</button>
  </form>
  <a href="dashboard.php">&larr; Back to dashboard</a>
</div>
</body>
</html>
