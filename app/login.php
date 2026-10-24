<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/db.php';
require __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

// One message for every failure: unknown user, wrong password, locked, inactive.
const GENERIC_ERROR = 'Invalid username or password, or account temporarily locked.';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token    = (string)($_POST['csrf'] ?? '');
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    if (!csrf_check($token)) {
        http_response_code(400);
        $error = 'Your session expired. Please try again.';
    } else {
        $db = db_connect($config);
        $valid = preg_match('/^[A-Za-z0-9_.-]{3,50}$/', $username) === 1
              && $password !== ''
              && strlen($password) <= 200;

        if (!$valid) {
            burn_cpu($password);
            audit($db, null, $username, 'LOGIN_FAILED', 'login.php', false, 'invalid input format');
            $error = GENERIC_ERROR;
        } elseif (attempt_login($db, $username, $password)) {
            $db->close();
            header('Location: dashboard.php');
            exit;
        } else {
            $error = GENERIC_ERROR;
        }
        $db->close();
    }
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GrantDB - Sign in</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f3f4f6;margin:0;display:grid;place-items:center;min-height:100vh}
  form{background:#fff;padding:2rem;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.12);width:320px}
  h1{font-size:1.25rem;margin:0 0 1rem}
  label{display:block;margin:.75rem 0 .25rem;font-size:.9rem}
  input{width:100%;padding:.55rem;border:1px solid #9ca3af;border-radius:6px;box-sizing:border-box}
  button{margin-top:1.25rem;width:100%;padding:.65rem;border:0;border-radius:6px;background:#1d4ed8;color:#fff;font-size:1rem;cursor:pointer}
  .err{background:#fee2e2;color:#991b1b;padding:.6rem;border-radius:6px;margin-bottom:.75rem;font-size:.9rem}
</style>
</head>
<body>
<form method="post" action="login.php" autocomplete="off">
  <h1>Research Grant System</h1>
  <?php if ($error !== ''): ?>
    <div class="err" role="alert"><?= h($error) ?></div>
  <?php endif; ?>
  <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
  <label for="username">Username</label>
  <input id="username" name="username" maxlength="50" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" maxlength="200" required>
  <button type="submit">Sign in</button>
</form>
</body>
</html>
