# Phase 3: Secure Authentication

## 1. Design
The PHP application authenticates users against `grantdb.users`. It connects to the database only as `app_login`, the service account from Phase 2, which can read the login columns, update the lockout counters and insert audit rows, and nothing else.

## 2. Controls implemented

| Control | Where | Threat it addresses |
|---|---|---|
| Passwords stored with `password_hash` (bcrypt, per-user salt) | `tools/seed_users.php` | Stolen database reveals passwords |
| `password_verify` for checking | `includes/auth.php` | Timing-safe comparison, no plaintext handling |
| Prepared statements for every query | `includes/auth.php`, `bootstrap.php` | SQL injection on the login page |
| One generic error message for every failure | `login.php` | Username enumeration |
| Equal work for unknown users (`burn_cpu`) | `bootstrap.php`, `auth.php` | Username enumeration through response time |
| Lockout: 5 failed attempts, 15 minutes | `auth.php`, `users.failed_attempts`, `users.locked_until` | Brute force, credential stuffing |
| Lock time compared with the database clock (`NOW()`) | `auth.php` | Clock and timezone mismatches |
| New session id after login (`session_regenerate_id`) | `auth.php` | Session fixation |
| Cookie flags: HttpOnly, SameSite=Strict, Secure (once HTTPS is on) | `bootstrap.php` | Cookie theft by script, cross-site requests |
| `session.use_strict_mode`, cookies only | `bootstrap.php` | Session id injection through URL |
| Idle timeout of 15 minutes | `bootstrap.php` | Abandoned sessions |
| CSRF token on login and logout forms | `bootstrap.php`, forms | Forced actions from other sites |
| Logout is POST only, destroys session and cookie | `logout.php` | Session reuse after logout |
| Output escaped with `h()` | all pages | Cross-site scripting |
| Security headers (CSP, X-Frame-Options, nosniff, no-store) | `bootstrap.php` | Clickjacking, content sniffing, cached pages |
| Errors logged, never displayed | `bootstrap.php`, `db.php` | Information disclosure |
| Credentials in `config.php`, ignored by Git, blocked by `.htaccess` | `config.example.php` | Secrets in the repository or served over HTTP |
| Every login, failure, lockout and logout written to `audit_log` | `bootstrap.php` `audit()` | Repudiation, incident investigation (Phase 10) |

## 3. Known limitations (be ready to discuss)
- Connection is HTTP on localhost. HTTPS and database TLS come in Phases 6 and 9. The `Secure` cookie flag is set automatically once HTTPS is on.
- No password rehash on login: `app_login` has no UPDATE right on `password_hash`, by design (least privilege).
- No multi-factor authentication. It would be the next improvement.
- Lockout is per account, not per IP, so an attacker can lock a victim's account (a denial of service trade-off).
- After a lockout expires, one more failed attempt locks the account again, until a successful login resets the counter.

## 4. Tests and evidence
Use `http://localhost/grantdb/login.php`. Passwords for the demo accounts are in `Documents\app-passwords.txt` (outside the repo).

| # | Test | Expected | Evidence file |
|---|---|---|---|
| 1 | Valid login (`app_pi`) | Dashboard shows username and role PI | `P3-01-login-success.png` |
| 2 | Wrong password for `app_pi` | Generic error message | `P3-02-wrong-password.png` |
| 3 | Unknown username | The same generic message | `P3-03-unknown-user.png` |
| 4 | Five wrong passwords on `app_auditor`, then the correct one | Still refused (locked) | `P3-04-lockout.png` |
| 5 | `SELECT username, failed_attempts, locked_until FROM users;` as root | Counter and lock time set | `P3-05-lockout-db-row.png` |
| 6 | `SELECT username, LEFT(password_hash,7), LENGTH(password_hash) FROM users;` as root | `$2y$10$` prefix, length 60 | `P3-06-hash-format.png` |
| 7 | Open `dashboard.php` with no session | Redirected to login | `P3-07-no-session-redirect.png` |
| 8 | Sign out, then press Back and reload | Redirected to login | `P3-08-after-logout.png` |
| 9 | Browser DevTools, Application, Cookies | `GRANTSESSID` with HttpOnly and SameSite Strict | `P3-09-cookie-flags.png` |
| 10 | Edit the hidden `csrf` field in DevTools and submit | "Your session expired" error, HTTP 400 | `P3-10-csrf-rejected.png` |
| 11 | `SELECT event_time, username, action, success, details FROM audit_log ORDER BY audit_id DESC LIMIT 20;` | One row per event above | `P3-11-audit-log.png` |
| 12 | Open `http://localhost/grantdb/config.php` | 403 Forbidden | `P3-12-config-blocked.png` |

Add one sentence per test to `docs/notes.md` saying what it proves.
