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
  ## Phase 5, Test A (re-test): Always-true bypass neutralized
- Same payload as Phase 4: q=%' OR '1'='1
- Evidence: P5-02-always-true-blocked.png (injection attempt) vs
  P5-02-blank-search-baseline.png (ordinary empty search) — identical output.
- Why: input validation rejects quote/equals characters, resetting q to '';
  the prepared statement also means the payload text, even if it reached
  the query, could never be parsed as SQL syntax, only as literal data.
- Proves: the payload now produces exactly the same result as a legitimate
  blank search — no special effect, no bypass of intended logic.
  ## Phase 5, Test B (re-test): UNION-based leak blocked
- Same payload as Phase 4: q=%' UNION SELECT user_id, username, password_hash FROM users -- -
- Evidence: P5-03-union-blocked.png
- Result: page shows the same 7 ordinary proposals (titles and statuses only).
  No usernames, no password hashes, nothing from the users table appeared.
- Why: (1) input validation rejects the quote, underscore, comma and equals
  characters, resetting the search term to empty; (2) even without
  validation, the prepared statement fixes the query structure before any
  user input is attached, so a UNION SELECT cannot be injected as new SQL -
  it is only ever treated as literal text to search for in titles;
  (3) app_search can only SELECT 3 columns on proposals, so even a
  successful bypass could never read the users table at all.
- Proves: all three layers of the fix (prepared statement, input
  validation, least-privileged account) independently prevent this attack,
  not just one of them.
  ## Phase 6: Sensitive data encryption (AES-256-GCM)
- Encrypted national_id_enc, phone_enc, bank_account_enc for all 3 researchers
  using application-level AES-256-GCM (not MySQL's AES_ENCRYPT, to keep the
  key out of SQL query text/logs).
- P6-01-decrypt-verification.png: all 3 rows decrypt back to their exact
  original fake values, proving correctness.
- P6-02-raw-encrypted-bytes.png: SELECT HEX(national_id_enc) as root shows
  only ciphertext - confirms encryption is real, not just hidden by RBAC.
- Key lives in keys/encryption.key.php, generated with random_bytes(32),
  outside both web-servable folders, excluded from Git.
- Known gap: data in transit (HTTP, no DB TLS) still pending - addressed in
  Phase 9. Full analysis: docs/phase6_data_protection.md.
  Phase 7: Database auditing and monitoring

Extended the existing audit_log mechanism (built in Phase 3) to cover the 4 remaining required categories: access to sensitive information, record modification, record deletion, and administrative actions. Each new action calls the same audit() function from bootstrap.php, writing who, what, when, which resource and whether it succeeded.

New pages: view_researchers.php (VIEW_SENSITIVE), update_proposal.php (UPDATE_RECORD), delete_proposal.php (DELETE_RECORD), admin_users.php (ADMIN_ACTION), audit_log.php (Auditor's view of the log, with 2 detection queries).
app_login needed 3 extra privilege grants to make these pages work (sql/07_app_login_grants.sql): SELECT/UPDATE/DELETE on proposals, SELECT on researchers, SELECT on audit_log, and a column-level UPDATE on users (is_active, locked_until, failed_attempts). This is itself a least-privilege demonstration: MySQL correctly refused the UPDATE on is_active until the exact column was granted, proving Phase 2's column-level privileges are real, not just configured and unused.
Test: update a proposal's status (P7-01-update-record.png)
Logged in as app_officer, changed proposal 4 from Submitted to Under Review via update_proposal.php.
Proves: record modification is logged with the resource identified down to the exact row (proposals:4).
Test: blocked deletion attempt (P7-02-delete-blocked.png)
Tried to delete proposal 1 (status Approved, not Draft) via delete_proposal.php. The app refused and showed "this attempt was logged."
Proves: a blocked/refused attempt is still written to audit_log, not only successful actions — important for investigating someone who tries and fails.
Test: successful deletion (P7-03-delete-success.png)
Deleted proposal 7 (status Draft) successfully.
Proves: a legitimate deletion under the allowed condition (Draft only) is logged as a successful DELETE_RECORD event.
Test: access to sensitive data (P7-04-view-sensitive.png)
Logged in as app_dba, opened view_researchers.php, which decrypts and displays the 3 researchers' Restricted-classification data (national ID, phone, bank account) from Phase 6.
Proves: every time sensitive data is viewed, it is logged individually per row viewed (researchers:1, researchers:2, researchers:3), not just once per page load.
Test: administrative action (P7-05-admin-action.png)
Logged in as app_dba, deactivated test account app_pi3 (user ID 8) via admin_users.php, then reactivated it afterward.
Proves: privileged account-management actions by the DBA role are individually logged, which Phase 10's incident investigation will rely on.
Test: brute-force detection (P7-06-detection-bruteforce.png)
Deliberately failed 3 logins in a row against app_pi with a wrong password, then logged in as app_auditor and opened audit_log.php.
Result: the page's "Detection 1" query automatically grouped and flagged app_pi with 3 failures within 24 hours.
Proves: the collected log data can actually detect a brute-force pattern, not just record individual events in isolation — this is the brief's explicit requirement to demonstrate detection, not only collection.
Test: raw audit log (P7-07-audit-log-raw.png)
Viewed the full recent-events table on audit_log.php, showing every event with timestamp, username, action, resource, success, and IP address together.
Proves: all 5 required questions (who/what/when/which resource/was it successful) are answerable from a single table.
Test: direct SQL query evidence (P7-08-sql-query-evidence.png)
Ran the same brute-force detection query (sql/07_audit_queries.sql, query 1) directly in phpMyAdmin against the database, outside the PHP application.
Proves: the detection logic isn't hidden inside the app — the same result can be reproduced with a plain SQL query, which matters for an auditor who may not want to rely on the application layer at all.
Known limitations
Detection is manual (an auditor opens the page or runs a query) — no automated alerting is implemented.
The "3 failures / 24h" and "off-hours" thresholds in the detection queries are illustrative, not tuned to real traffic.
audit_log itself is protected only by Phase 2's RBAC; it is not tamper-evident (no append-only storage or hash chaining), so a sufficiently privileged DBA account could in theory alter past entries. Flagged as a realistic limitation of a single-VM lab setup, not solved here.
## Phase 8: Backup and recovery
Created a full `mysqldump` backup of `grantdb` (with `--routines --triggers --hex-blob`), simulated a critical table loss by dropping `researchers` (the table holding Phase 6's encrypted sensitive data), restored from the backup, and verified the recovered data byte-for-byte, not just that the table existed again.

### Test: backup created (P8-01-backup-created.png)
- Ran `mysqldump` against `grantdb`, producing a 47,758-byte `.sql` file.
- Proves: a reproducible backup procedure exists and actually captures the database content.

### Test: simulated disaster (P8-02-table-dropped.png, P8-03-app-broken.png)
- A plain `DROP TABLE researchers;` was refused by MariaDB (error 1451, foreign key constraint) because `proposals` references it — referential integrity acting as a safeguard on its own.
- Disabled foreign key checks and dropped the table to simulate a scenario where that safeguard is bypassed (e.g. an admin script run carelessly).
- Confirmed the table was really gone (10 tables instead of 11), and that `view_researchers.php` genuinely broke (HTTP 500) as a result.
- Proves: this was a real, demonstrated loss of a critical table, not a staged example.

### Test: restore (P8-04-restore-command.png, P8-05-table-restored.png)
- Restored from the backup with `mysql -u root grantdb` (piped in via PowerShell).
- `researchers` reappeared with the correct row count (3).
- Proves: the backup can actually be used to bring a dropped table back.

### Test: integrity verification (P8-06-decrypt-verified.png, P8-07-app-working-again.png)
- Re-ran `tools/decrypt_check.php`: all 3 researchers' encrypted data decrypted correctly, and the raw ciphertext bytes matched exactly what they were before the table was dropped.
- Re-opened `view_researchers.php` in the browser: worked again, same data as before.
- Proves: the brief's requirement that "simply showing a backup file exists is not sufficient" is met — the actual content was verified correct, not just present.

### Real problem found and fixed during this phase (not staged - documented honestly)
The first restore attempt (before adding `--hex-blob` to the backup command) completed with no errors, but corrupted the 3 encrypted columns: `decrypt_check.php` failed with "wrong key or data was tampered with" (AES-GCM's own authentication check caught it), and the raw bytes showed repeated `3f` (the `?` character) where random ciphertext should be. Root cause: piping the backup file through PowerShell as text (`Get-Content | mysql.exe`) is unsafe for raw binary data, even though it's harmless for ordinary text. Fixed by adding `--hex-blob` to `mysqldump`, which stores binary columns as plain ASCII hex text, immune to this. The 3 affected rows were independently recovered from the original Phase 4 plaintext seed data and re-encrypted, then the whole backup/drop/restore cycle was redone cleanly with the fix, producing the final evidence above.

### Second, unrelated problem found and fixed during this phase
While investigating an unrelated "access denied" error for `dba_admin`, found that MariaDB's own internal `mysql.db` privilege table was genuinely corrupted (Aria storage engine checksum error) and `role_dba` had lost its database-wide privilege grant entirely. This is very likely the same root cause as the unexplained "all accounts and roles missing" incident from Phase 3. Repaired with `mysqlcheck --auto-repair`, which recovered by wiping the corrupted rows, then restored the lost grants using `sql/08_repair_role_grants.sql` (deliberately written to skip the password-setting lines of `02_users_roles.sql`, so no passwords were reset). This also showed a real gap in the backup procedure itself: it only covers the `grantdb` database, not MariaDB's own `mysql` system database (accounts/roles/grants) — documented as a known limitation.

### Known limitations
- Manual/on-demand backup only, no scheduling.
- Full-database restore only, not table-level.
- Backup files are not encrypted at rest (contain the same ciphertext as the live DB, plus plaintext for non-encrypted columns).
- Stored locally only, single point of failure if the VM is lost.
- Backup procedure does not cover the `mysql` system database (accounts/roles), a gap this phase's own incident exposed directly.
## Phase 9: Database hardening
Reviewed the Phase 1 baseline (docs/phase9_hardening.md) item by item and addressed all 12 required areas: default/shared accounts, unnecessary database users, unnecessary databases, excessive privileges, weak application accounts, network exposure, logging configuration, configuration files, unnecessary features/services, file permissions, patch/update status, and backup protection.

### Test: default/shared accounts fixed (P9-after-01 to P9-after-04)
- Set a root password, dropped the redundant `root@127.0.0.1` and `root@::1` accounts (kept only `root@localhost`), and dropped `pma@localhost` and `labuser@localhost` (neither had a legitimate current use).
- Before dropping the IP-based root accounts, confirmed phpMyAdmin actually connects via `127.0.0.1`, not `localhost`, and switched its config to `localhost` first to avoid locking myself out.
- Proves: no more passwordless administrative access, and the account list only contains what's actually needed.

### Test: unnecessary users investigated, not blindly removed (no new screenshot, documented in docs/phase9_hardening.md)
- Found two accounts not created by `sql/02_users_roles.sql`: `app_search` and `app_vuln`. Checked their grants and my own Phase 4/5 notes before touching anything, and confirmed they are the deliberate accounts used to demonstrate the Phase 4 SQL injection attack and the Phase 5 fix, not stale leftovers.
- Proves: hardening means investigating before removing, not deleting anything that looks unusual.

### Test: unnecessary databases removed (P9-after-05, P9-after-06)
- Dropped the default `test` database. Left `university_security` untouched since it belongs to a separate, unrelated course exercise.

### Test: excessive privileges reviewed (P9-after-07)
- Confirmed `app_login` (the account the real application actually uses) has only scoped, least-privilege grants via `SHOW GRANTS`, nowhere close to root's `ALL PRIVILEGES`. Root's broad privileges are necessary for it to function as the admin account and are never used by the application itself.

### Test: network exposure fixed (P9-after-08 to P9-after-11)
- Added `bind-address=127.0.0.1` to `my.ini`, restarted MySQL, and confirmed via `netstat` that the server now listens only on `127.0.0.1:3306` instead of `0.0.0.0:3306`/`[::]:3306`.
- Added a Windows Firewall inbound rule explicitly blocking external access to port 3306, as a second, independent layer of defense.
- Verified the application and phpMyAdmin still work locally after both changes.

### Test: logging configuration reviewed (P9-after-12)
- Confirmed MariaDB's own error log (`log_error`) is active with real content, including a line that independently proved the `bind-address` fix took effect ("Server socket created on IP: '127.0.0.1'").
- Deliberately left `general_log` and `slow_query_log` off: full query logging would write the plaintext values behind Phase 6's encrypted columns into an unprotected log file, which would undermine that work. The Phase 7 `audit_log` already covers accountability without that risk.

### Test: unnecessary features/services reviewed (P9-before-after-08)
- Checked the XAMPP Control Panel: only Apache and MySQL are running. FileZilla, Mercury, and Tomcat are present but were never started.

### Test: file permissions reviewed (P9-after-13)
- Checked Windows file permissions on `config.php` and `keys/encryption.key.php`, the two most sensitive files in the project. Both are restricted to the file owner, SYSTEM, and Administrators only — no broader group has access.

### Test: patch/update status documented (docs/phase9_hardening.md, item 11 detail)
- Checked MariaDB 10.4.32, PHP 8.2.12, and Apache 2.4.58 against current support status. MariaDB 10.4 reached end-of-life in June 2024; PHP 8.2 is past active support and reaches full end-of-life in December 2026; Apache 2.4.58 has 68 CVEs fixed in later releases, including one critical one.
- Decided to document the gap with a concrete remediation plan rather than attempt a risky in-place upgrade of three interdependent components this close to the project deadline, and emailed the professor to confirm this approach is acceptable.

### Test: backup protection fixed (P9-before-14, P9-after-14, P9-after-15)
- Encrypted the most recent backup with 7-Zip (AES-256, filenames also encrypted), then deleted the plaintext copy so it doesn't linger on disk.
- Verified both directions: extraction with a wrong password fails ("Data error: Wrong password?"), extraction with the correct password succeeds.
- Proves: the encryption is real and enforced, not just a cosmetic password box.

### Known limitations
- Backups are still stored locally only (single point of failure if the VM is lost) — accepted as reasonable for a single lab VM, not a production deployment.
- Patch/update status is documented with a remediation plan but not yet executed, a deliberate decision given the project timeline (see above).
- `general_log`/`slow_query_log` remain off by design; if deeper server-level query auditing were ever needed, it would require its own protected storage, which is out of scope here.
## Phase 10: Security incident investigation
Ran a simulated two-part incident against the live system — matching the brief's example of unauthorized access attempts plus unusual privileged-account activity — then investigated it using only the Phase 7 audit tools, as a real investigator would.

### Test: incident produced (not staged after the fact)
- Part A: 5 failed logins against `app_reviewer`, triggering the Phase 3 lockout automatically.
- Part B: immediately after, `app_dba` viewed all 3 researchers' Restricted data and deactivated another account (`app_pi2`).

### Test: detection (P10-01-detection-bruteforce.png, P10-02-detection-unusual-activity.png)
- `audit_log.php`'s two detection queries automatically flagged both halves: `app_reviewer` with 5 brute-force failures, and `app_dba` with 6 VIEW_SENSITIVE events and 1 ADMIN_ACTION in 24h.
- Proves: the Phase 7 detection logic works on a real, freshly-produced incident, not only on the earlier test data it was built against.

### Test: raw log reconstruction (P10-03-raw-log-incident-window.png)
- Read the raw `audit_log` table directly to build a full timeline: who, what, when, which resource, success/failure, down to the millisecond.
- Noticed the 3 VIEW_SENSITIVE events were only 4ms apart — too fast for a human reading 3 records, a genuine artifact of how the page logs each row as it renders all three at once. Documented honestly rather than overstating it as proof of malicious automation.

### Test: independent confirmation (P10-04-sql-direct-query.png, P10-05-account-states.png)
- Reproduced the brute-force detection with a direct SQL query, outside the application.
- Checked the `users` table directly: `app_reviewer` shows `locked_until` and `failed_attempts=5`; `app_pi2` shows `is_active=0` — the database state itself corroborates the log, not just the log's own claim about itself.

### Findings
Answered the brief's 7 required questions (what/when/who/which resources/what controls failed/what evidence/what corrective actions) in full in docs/phase10_incident_investigation.md. Key takeaway: the lockout and audit logging controls worked correctly and caught everything; the gaps exposed were the lack of real-time alerting, the audit log not being tamper-evident against a sufficiently privileged account, and no MFA for the DBA role.

### Known limitations
- This was a simulated incident performed by the project author, not a real attacker — evaluated structurally (what the logs would show, what controls would/wouldn't catch it).
- Both parts ran from the same machine, so IP-based anomaly detection couldn't be demonstrated (both show `::1`).


