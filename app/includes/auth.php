<?php
declare(strict_types=1);

/**
 * Checks credentials. Returns true and fills the session on success.
 * Every failure path returns false WITHOUT telling the caller why, so the
 * login page can show one identical message (no username enumeration).
 */
function attempt_login(mysqli $db, string $username, string $password): bool
{
    // Prepared statement: the username is data, never SQL.
    $stmt = $db->prepare(
        'SELECT u.user_id, u.username, u.password_hash, u.is_active, r.role_name,
                (u.locked_until IS NOT NULL AND u.locked_until > NOW()) AS is_locked
           FROM users u
           JOIN app_roles r ON r.role_id = u.role_id
          WHERE u.username = ?'
    );
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$row) {
        burn_cpu($password);
        audit($db, null, $username, 'LOGIN_FAILED', 'login.php', false, 'unknown user');
        return false;
    }

    $uid = (int)$row['user_id'];

    if ((int)$row['is_locked'] === 1) {
        burn_cpu($password);
        audit($db, $uid, $username, 'LOGIN_BLOCKED', 'login.php', false, 'account locked');
        return false;
    }

    if ((int)$row['is_active'] !== 1) {
        burn_cpu($password);
        audit($db, $uid, $username, 'LOGIN_FAILED', 'login.php', false, 'inactive account');
        return false;
    }

    if (!password_verify($password, $row['password_hash'])) {
        // locked_until is evaluated first, with the counter value from before this failure.
        $max = MAX_FAILED_ATTEMPTS;
        $min = LOCKOUT_MINUTES;
        $upd = $db->prepare(
            'UPDATE users
                SET locked_until    = IF(failed_attempts + 1 >= ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), locked_until),
                    failed_attempts = failed_attempts + 1
              WHERE user_id = ?'
        );
        $upd->bind_param('iii', $max, $min, $uid);
        $upd->execute();
        $upd->close();

        audit($db, $uid, $username, 'LOGIN_FAILED', 'login.php', false, 'bad password');

        $chk = $db->prepare('SELECT (locked_until IS NOT NULL AND locked_until > NOW()) AS l FROM users WHERE user_id = ?');
        $chk->bind_param('i', $uid);
        $chk->execute();
        $now = $chk->get_result()->fetch_assoc();
        $chk->close();
        if ($now && (int)$now['l'] === 1) {
            audit($db, $uid, $username, 'ACCOUNT_LOCKED', 'users', false,
                  'locked for ' . LOCKOUT_MINUTES . ' minutes');
        }
        return false;
    }

    // Success: reset counters, then issue a NEW session id (prevents session fixation).
    $ok = $db->prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = NOW() WHERE user_id = ?');
    $ok->bind_param('i', $uid);
    $ok->execute();
    $ok->close();

    session_regenerate_id(true);
    $_SESSION['user_id']       = $uid;
    $_SESSION['username']      = $row['username'];
    $_SESSION['role']          = $row['role_name'];
    $_SESSION['login_time']    = time();
    $_SESSION['last_activity'] = time();

    audit($db, $uid, $username, 'LOGIN', 'login.php', true, null);
    return true;
}
