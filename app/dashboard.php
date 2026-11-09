<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';

send_security_headers();
start_secure_session();
require_login();

// What each role is meant to do. The database enforces it too (Phase 2).
$menus = [
    'DBA'            => 'Full administration of the grantdb database.',
    'GrantsOfficer'  => 'Manage proposals, awards and budgets. No access to national IDs or bank data.',
    'PI'             => 'Create and submit your own proposals. Read-only access to grants.',
    'Reviewer'       => 'Review submitted proposals. The identity of the PI is hidden (blind review).',
    'FinanceOfficer' => 'Record expenditures and read banking data needed for payment.',
    'Auditor'        => 'Read-only access to the audit log and financial records.',
];
$role = (string)$_SESSION['role'];

// Phase 7: which audit/admin demo pages this role can reach.
$links = [];
if (in_array($role, ['DBA', 'FinanceOfficer', 'Auditor'], true)) {
    $links['view_researchers.php'] = 'View researcher sensitive data';
}
if (in_array($role, ['GrantsOfficer', 'DBA'], true)) {
    $links['update_proposal.php'] = 'Update a proposal status';
    $links['delete_proposal.php'] = 'Delete a Draft/Withdrawn proposal';
}
if ($role === 'DBA') {
    $links['admin_users.php'] = 'Admin: manage user accounts';
}
if (in_array($role, ['Auditor', 'DBA'], true)) {
    $links['audit_log.php'] = 'View audit log';
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GrantDB - Dashboard</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f3f4f6;margin:0;padding:2rem}
  .card{background:#fff;max-width:640px;margin:auto;padding:2rem;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.12)}
  h1{font-size:1.3rem;margin-top:0}
  dt{font-weight:600;margin-top:.75rem}
  dd{margin:0}
  button{margin-top:1.5rem;padding:.55rem 1.1rem;border:0;border-radius:6px;background:#991b1b;color:#fff;cursor:pointer}
</style>
</head>
<body>
<div class="card">
  <h1>Welcome, <?= h((string)$_SESSION['username']) ?></h1>
  <dl>
    <dt>Role</dt>
    <dd><?= h($role) ?></dd>
    <dt>Your permissions</dt>
    <dd><?= h($menus[$role] ?? 'No permissions defined for this role.') ?></dd>
    <dt>Signed in at</dt>
    <dd><?= h(date('Y-m-d H:i:s', (int)$_SESSION['login_time'])) ?></dd>
  </dl>
  <?php if ($links): ?>
  <dl>
    <dt>Available actions</dt>
    <dd>
      <?php foreach ($links as $href => $label): ?>
        <div><a href="<?= h($href) ?>"><?= h($label) ?></a></div>
      <?php endforeach; ?>
    </dd>
  </dl>
  <?php endif; ?>
  <form method="post" action="logout.php">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
    <button type="submit">Sign out</button>
  </form>
</div>
</body>
</html>
