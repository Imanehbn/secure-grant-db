# Evidence Notes: Before Hardening (16 Oct 2026)

**Environment:** Windows 11 VM (VMware), XAMPP, MariaDB 10.4.32, PHP 8.2.12,
Apache 2.4.58, phpMyAdmin.

## Capture 1: Server information (P9-before-01-server-info.png)
- **Observation:** The page states "SSL is not used". The session is connected
  as root@localhost over TCP/IP.
- **What it proves:** The connection between the client and the database is not
  encrypted, and the administrator account is the one being used.
- **Risk:** Data and credentials sent to the database could be read by anyone
  who can capture the traffic (data in transit). Using root exposes full
  administrative power.
- **Planned fix:** Enable TLS for database connections; use a dedicated
  least-privileged account for the application.

## Capture 2: Database accounts (P9-before-02-users.png)
- **Observation:** 5 accounts exist: root@localhost, root@127.0.0.1, root@::1,
  pma@localhost and labuser@localhost. The first four show an empty password
  column; only labuser has a password hash.
- **What it proves:** Anyone who can reach the server locally can log in as the
  database administrator without a password. Three separate root accounts
  triple the exposure. The pma account also has no password.
- **Risk:** Full compromise of every database with no authentication effort.
- **Planned fix:** Set a strong root password, remove redundant root accounts,
  set a password for or remove pma, and review the purpose of labuser.
- **Note:** The labuser hash is partly visible. Blur it before sharing.

## Capture 3: Databases present (P9-before-03-databases.png)
- **Observation:** information_schema, mysql, performance_schema, phpmyadmin,
  test, university_security.
- **What it proves:** The default `test` database is present. It is an
  unnecessary default component and part of the attack surface.
  university_security is not part of this project.
- **Planned fix:** Drop `test`. Confirm whether university_security is needed;
  if it belongs to another exercise, leave it untouched.

## Capture 4: Privileges of root (P9-before-04-root-grants.png)
- **Observation:** root has GRANT ALL PRIVILEGES on *.* and a GRANT PROXY
  privilege.
- **What it proves:** Root has unrestricted control over every database and can
  grant privileges to others. This is the opposite of least privilege.
- **Risk:** If the application ran as root, a single SQL injection would give
  an attacker full control of the server.
- **Planned fix:** Create separate roles and accounts (Phase 2) and never let
  the application connect as root.

## Capture 5: Open database port (P9-before-05-port.png)
## Capture 5: Open database port (P9-before-05-port.png)
- **Observation:** `netstat -an | findstr 3306` shows TCP 0.0.0.0:3306 and
  [::]:3306 in the LISTENING state.
- **What it proves:** The database server accepts connections on every network
  interface (IPv4 and IPv6), not only on the local loopback address. Combined
  with root accounts that have no password (Capture 2), any machine that can
  reach this host on port 3306 could attempt to log in as administrator.
- **Risk:** Unnecessary network exposure of the database; remote brute-force
  and unauthorized access attempts.
- **Planned fix:** Set `bind-address=127.0.0.1` in my.ini so MariaDB only
  accepts local connections, restrict the port with the Windows firewall,
  and re-run netstat to show 127.0.0.1:3306 only.

## Capture 6: Configuration file (P9-before-06-my.ini)
- **Observation:** Copy of the default my.ini taken before any change.
- **What it proves:** This is the baseline configuration. It will be compared
  with the hardened version in Phase 9 (bind-address, logging, and other settings).
  ## Phase 1: Schema import
- The script created grantdb with 11 tables and seeded 6 roles. The 15
  statements executed without failure. This is the baseline for Phase 2
  ## Phase 2: Privilege tests for pi_user1 (P2-04-to-08-pi-user1-tests.png)
- **Allowed:** SELECT COUNT(*) FROM proposals returns 0. The PI can read
  proposals (the table is empty at this stage).
- **ERROR 1143 on bank_account_enc:** column-level privilege hides banking
  data from PIs, which limits damage if a PI account is stolen.
- **ERROR 1142 on users:** PIs have no access to credentials or password hashes.
- **ERROR 1143 on proposals.status:** a PI cannot set their own proposal to
  Approved. The only route to submission is the stored procedure
  sp_submit_proposal, which moves a proposal from Draft to Submitted only.
- **ERROR 1142 on DELETE:** no role except the DBA can delete proposals.
- **Conclusion:** the database itself enforces least privilege, independently
  of what the application does.
  ## Phase 2: Privilege tests for the other roles (P2-09 to P2-13)
- reviewer1: ERROR 1143 on proposals.pi_id (blind review) and ERROR 1142 on grants.
- grants_officer1: ERROR 1143 on researchers.national_id_enc and ERROR 1142 on
  DELETE FROM grants. The research office manages awards but sees no identity
  or banking data and cannot delete.
- finance1: reads bank_account_enc (needed to pay researchers) but gets
  ERROR 1142 on UPDATE grants. Separation of duties between awarding and paying.
- auditor1: reads audit_log but gets ERROR 1142 on INSERT. A read-only auditor
  cannot tamper with the evidence.
- app_login: reads credentials only; ERROR 1142 on proposals, so a SQL
  injection in the login page cannot reach business data.
- Note: allowed queries return 0 because tables are empty at this stage; they
  prove the privilege, not the data.
- Incident: logins failed with ERROR 1045 because a password stored via
  copy-paste contained a trailing space. Resolved by generating passwords
  with a script and reading them from a file outside the repository.
  ## Phase 3: Secure authentication (24 Oct 2026)

**Implementation:** PHP login (app/login.php, includes/auth.php, bootstrap.php)
connected as the least-privileged account app_login. Passwords hashed with
password_hash (bcrypt), prepared statements, CSRF tokens, secure session
settings, lockout after 5 failed attempts for 15 minutes, audit logging.
Design and control list: docs/phase3_authentication.md.

### Test 1: valid login (P3-01-login-success.png)
- app_pi signs in and sees the dashboard with role PI and its permissions.
- Proves: the full path works (form, prepared query, bcrypt verification,
  session creation, role lookup) using only the app_login account.

### Test 2: wrong password (P3-02-wrong-password.mp4)
- Generic message: "Invalid username or password, or account temporarily locked."
- Proves: the page does not say which part was wrong.

### Test 3: unknown username (P3-03-unknown-user.mp4)
- Exactly the same message as test 2.
- Proves: no username enumeration. An attacker cannot learn which accounts exist.

### Test 4: account lockout (P3-04-lockout.mp4)
- After 5 wrong passwords on app_auditor, the correct password is refused.
- Proves: brute force and credential stuffing against one account are stopped.
- Trade-off: lockout is per account, so an attacker could lock a victim out
  (denial of service). Mitigation would be per-IP throttling or MFA.

### Test 5: lockout stored in the database (P3-05-lockout-db-row.png)
- app_auditor shows failed_attempts = 5 and a locked_until time 15 minutes
  later; app_pi shows its own failed attempts.
- Proves: the lock is enforced in the database (compared with NOW() in SQL),
  not only in the page, and cannot be bypassed by changing the browser.

### Test 6: password hash format (P3-06-hash-format.png)
- All stored hashes start with $2y$10$ and are 60 characters long.
- Proves: passwords are stored as salted bcrypt hashes, never as plain text.
  A stolen users table does not reveal the passwords directly.

### Test 7: no session (P3-07-no-session-redirect.mp4)
- Opening dashboard.php in a private window redirects to login.php.
- Proves: protected pages check the session on every request.

### Test 8: after logout (P3-08-after-logout.mp4)
- After Sign out, Back and reload lead to the login page.
- Proves: logout destroys the server-side session and the cookie, and the
  page is sent with no-store cache headers.

### Test 9: session cookie flags (P3-09-cookie-flags.png)
- GRANTSESSID has HttpOnly and SameSite=Strict, and no expiry (session cookie).
  Secure is off only because the lab runs on HTTP; the code sets it
  automatically once HTTPS is enabled.
- Proves: JavaScript cannot read the session id (limits XSS theft) and the
  browser does not send it on cross-site requests (limits CSRF).

### Test 10: CSRF token rejected (P3-10-csrf-rejected.mp4)
- With the hidden csrf field altered in DevTools, the form is rejected with
  "Your session expired" before any credential check.
- Proves: a login or logout request cannot be forged from another site
  without the per-session token.

### Test 11: audit trail (P3-11-audit-log.png)
- audit_log contains LOGIN, LOGIN_FAILED (bad password / unknown user),
  LOGIN_BLOCKED, ACCOUNT_LOCKED and LOGOUT events with user, time and result.
- Proves: authentication events are traceable for incident investigation
  (Phase 10).

### Test 12: configuration file blocked (P3-12-config-blocked.png)
- http://localhost/grantdb/config.php returns 403 Forbidden.
- Proves: the database password cannot be downloaded through the web server.
  The file is also ignored by Git.

### Known limitations
- HTTP only for now; HTTPS and database TLS are planned (Phases 6 and 9).
- No multi-factor authentication.
- PHP and MariaDB use different timezones (dashboard shows 03:34, audit log
  01:34); to be aligned before Phase 7.

### Incident: database accounts missing (24 Oct)
- app_login could not connect (ERROR 1045); ALTER USER failed with ERROR 1396.
  SELECT user, host FROM mysql.user showed all 7 application accounts and 7
  roles missing, while the grantdb tables were intact.
- Cause: not determined. Accounts live in the mysql system database, not in grantdb.
- Recovery: re-ran sql/02_users_roles.sql with newly generated passwords
  (stored outside the repository) and verified with SHOW GRANTS.
- Lesson: user and role definitions must be backed up too (Phase 8), and the
  privilege script must be re-runnable (CREATE OR REPLACE USER).
  ## Phase 4, Test A: Always-true WHERE bypass (P4-02-always-true.png)
- Payload: q=%' OR '1'='1
- Final query: ...WHERE title LIKE '%%' OR '1'='1'
- Result: all 7 proposals returned, including both CONFIDENTIAL DRAFT ones
  that should not be visible in a public search.
- Root cause: user input concatenated directly into SQL text (search.php).
- Proves: an attacker needs no valid search term to bypass filtering logic
  entirely — a single quote and a tautology defeats the WHERE clause.
  ## Phase 4, Test B: UNION-based data exfiltration (P4-03-union-leak.png)
- Payload: q=%' UNION SELECT user_id, username, password_hash FROM users -- -
- Result: all 8 application accounts' usernames and full bcrypt password
  hashes displayed in the search results, disguised as proposal rows.
- Root cause: (1) user input concatenated into SQL text, allowing an
  attacker-controlled UNION SELECT; (2) app_vuln has SELECT on every table
  in grantdb, not just proposals, so the UNION could reach an unrelated
  table with no privilege barrier at all.
- Security impact: an attacker with no credentials could harvest every
  account's password hash and attempt offline cracking, completely
  bypassing the Phase 3 login protections (lockout, rate limiting) since
  those only apply to the login form, not this page.
- Compare to Phase 3: app_login (the real login account) has NO SELECT
  privilege on password_hash at all for other users' rows context -- it
  can only read it for the authentication check itself, and critically
  this vulnerable page was never meant to touch the users table in the
  first place; it only could because app_vuln's privileges were not
  scoped to the page's actual needs.