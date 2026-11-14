# Phase 10: Security Incident Investigation

## Scenario
A simulated incident was run against the live system, matching the brief's example: "several unauthorized attempts have been made to access sensitive information. A privileged account has also performed unusual database operations." Two linked events were produced on the system and then investigated using only the evidence the system actually captured (the `audit_log` table and its detection queries from Phase 7), exactly as a real investigator would — no log entries were written by hand or edited after the fact.

**Part A:** 5 failed login attempts were made against `app_reviewer` using the correct username and a wrong password each time.

**Part B:** Immediately after, `app_dba` (a privileged account with access to Restricted-classification researcher data) logged in, viewed all 3 researchers' sensitive records in rapid succession, and deactivated another user account (`app_pi2`, user ID 7).

## Investigation evidence

### Detection 1: possible brute-force login (P10-01-detection-bruteforce.png)
`audit_log.php`'s brute-force query flagged `app_reviewer`: **5 failures** between `2026-11-14 15:33:13.115` and `2026-11-14 15:33:40.951`.

### Detection 2: sensitive/administrative/deletion activity (P10-02-detection-unusual-activity.png)
The same page's second detection query flagged `app_dba`:
- `VIEW_SENSITIVE`: 6 occurrences in the last 24h, last seen `2026-11-14 15:35:01.214`.
- `ADMIN_ACTION`: 1 occurrence, `2026-11-14 15:36:19.394`.

(The count of 6 for `VIEW_SENSITIVE` includes 3 events from a prior, unrelated session the previous day — `2026-11-13 19:56:02` — alongside the 3 from this incident. Separating old from new activity by timestamp was part of this investigation, not something the detection query does automatically; a real investigator has to read the raw log, not just trust the summary count.)

### Raw audit log, full incident window (P10-03-raw-log-incident-window.png)
The complete sequence of events for this incident, in order, read directly from the raw `audit_log` table (see table below).

### Direct SQL confirmation (P10-04-sql-direct-query.png)
The same two detection results were reproduced by running `sql/07_audit_queries.sql`'s queries directly in phpMyAdmin, outside the PHP application — confirming the findings don't depend on trusting the application layer.

### Database state check (P10-05-account-states.png)
`SELECT user_id, username, is_active, locked_until, failed_attempts FROM users WHERE user_id IN (4,7);` — confirms `app_reviewer` (user 4) shows a `locked_until` timestamp and `failed_attempts = 5`, and `app_pi2` (user 7) shows `is_active = 0`, matching the audit trail exactly. The database state itself corroborates the log, not just the log's own claim about itself.

## Incident timeline

| Time | Account | Event | Resource | Result |
|---|---|---|---|---|
| 15:33:13.115 | `app_reviewer` | LOGIN_FAILED | login.php | failed (bad password) |
| 15:33:20.644 | `app_reviewer` | LOGIN_FAILED | login.php | failed (bad password) |
| 15:33:27.181 | `app_reviewer` | LOGIN_FAILED | login.php | failed (bad password) |
| 15:33:34.739 | `app_reviewer` | LOGIN_FAILED | login.php | failed (bad password) |
| 15:33:40.951 | `app_reviewer` | LOGIN_FAILED | login.php | failed (bad password) |
| 15:33:40.953 | `app_reviewer` | ACCOUNT_LOCKED | users | locked for 15 minutes |
| 15:33:47.482 | `app_reviewer` | LOGIN_BLOCKED | login.php | refused (account locked) |
| 15:34:55.408 | `app_dba` | LOGIN | login.php | success |
| 15:35:01.210 | `app_dba` | VIEW_SENSITIVE | researchers:1 | success |
| 15:35:01.212 | `app_dba` | VIEW_SENSITIVE | researchers:2 | success |
| 15:35:01.214 | `app_dba` | VIEW_SENSITIVE | researchers:3 | success |
| 15:36:19.394 | `app_dba` | ADMIN_ACTION | users:7 | success (action=deactivate) |
| 15:37:29.978 | `app_dba` | LOGOUT | logout.php | success |
| 15:37:50.767 | `app_auditor` | LOGIN | login.php | success (investigation begins) |

## Findings

**What happened?**
Two linked suspicious patterns occurred within a 4-minute window. First, repeated failed login attempts were made against `app_reviewer` using correct credentials guessed incorrectly 5 times in a row — consistent with password-guessing/brute-force behavior. Immediately afterward, the privileged `app_dba` account accessed all 3 researchers' Restricted-classification records and deactivated another account, a pattern unusual enough in volume and timing to be automatically flagged by the audit system's own detection query.

**When did it happen?**
Between `2026-11-14 15:33:13` and `2026-11-14 15:37:29` (approximately 4 minutes, 16 seconds).

**Which account(s) were involved?**
- `app_reviewer` — target of the failed login attempts (not itself compromised; the account's own credentials were never correctly entered).
- `app_dba` — performed the sensitive-data access and the administrative action.

**What database resources were affected?**
- `users` table: `app_reviewer`'s account was automatically locked; `app_pi2` (user_id 7) was deactivated.
- `researchers` table: all 3 rows' Restricted-classification columns (national ID, phone, bank account) were decrypted and displayed.

**What security controls failed, and what worked?**
- **Worked:** the Phase 3 account lockout correctly stopped the brute-force attempt after 5 failures, without any manual intervention. The Phase 7 audit logging captured every single event with enough detail (who, what, when, which exact resource, success/failure) to fully reconstruct this timeline after the fact. The Phase 7 detection queries correctly flagged both halves of the incident automatically.
- **Gaps exposed by this investigation:**
  - Detection is manual — an auditor has to open `audit_log.php` or run a query; nothing paged or alerted anyone in real time while this was happening.
  - The `VIEW_SENSITIVE` detection counts activity over a rolling 24-hour window but doesn't distinguish "3 events from a normal page load yesterday" from "3 events from a suspicious session today" — a human investigator had to read the raw timestamps to separate the two, which would not scale to a busier system with more log volume.
  - `audit_log` is protected only by RBAC, not made tamper-evident (no append-only storage or hash chaining, flagged already in Phase 7). A privileged account like `app_dba` (if genuinely compromised) could in theory alter or delete the very rows that incriminate it, since `role_dba` has `ALL PRIVILEGES`.
  - No multi-factor authentication exists for privileged accounts. If `app_dba`'s password were the thing compromised (rather than this being the legitimate DBA doing something unusual), nothing beyond the password stood between an attacker and Restricted data.

**What evidence supports the findings?**
The `audit_log` raw table entries (cross-checked against the live `users` table state, which independently corroborates the lockout and deactivation), and the same results reproduced via direct SQL query outside the application layer — the findings do not rest on a single source.

**What corrective actions should be implemented?**
1. Automated alerting (e.g. a scheduled job or webhook) when either detection query returns a new match, instead of relying on an auditor manually opening the page.
2. Make `audit_log` append-only or hash-chained so a privileged account cannot quietly edit its own history — directly addresses the gap this investigation exposed.
3. Require MFA for the DBA role at minimum, since it has the broadest reach into Restricted data and administrative actions.
4. Extend the "unusual activity" detection to flag a privileged account's actions that happen immediately after a failed-login event on an unrelated account, since the two being close together in time is itself a signal worth flagging automatically, not just something a human investigator happens to notice.

## Known limitations
- This was a simulated incident on a lab VM, not a real attack; the `app_dba` login in Part B was performed by the project author, so "privileged account compromise" is being evaluated structurally (what the logs would show, what controls would/wouldn't catch it) rather than as a real adversarial event.
- Both parts were performed from the same machine, so the IP address column (`::1`, i.e. localhost) could not demonstrate IP-based anomaly detection — a real incident would likely show a different source IP for an attacker, which this test environment cannot produce.

## Evidence checklist
- `P10-01-detection-bruteforce.png`: Detection 1 flagging `app_reviewer`.
- `P10-02-detection-unusual-activity.png`: Detection 2 flagging `app_dba`.
- `P10-03-raw-log-incident-window.png`: raw audit log covering the full incident timeline.
- `P10-04-sql-direct-query.png`: same detections reproduced via direct SQL.
- `P10-05-account-states.png`: `users` table state confirming the lockout and deactivation independently of the log.
