<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/db.php';

send_security_headers();
start_secure_session();

// Logging out is a state change, so it needs POST and a valid CSRF token.
if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_SESSION['user_id'])
    && csrf_check((string)($_POST['csrf'] ?? ''))) {

    $db = db_connect($config);
    audit($db, (int)$_SESSION['user_id'], (string)$_SESSION['username'],
          'LOGOUT', 'logout.php', true, null);
    $db->close();
    destroy_session();
}

header('Location: login.php');
exit;
