# Phase 7: Database Auditing and Monitoring

## 1. What the brief requires
"The system must provide sufficient logging to support security monitoring and incident investigation." Six activity categories must be recorded where appropriate, and the log must answer five questions about each event, and we must demonstrate detection, not just collection.

## 2. Where each required category is logged

| Required category | Where it happens | `action` value in `audit_log` |
|---|---|---|
| Successful login | `app/includes/auth.php`, `attempt_login()` (built in Phase 3) | `LOGIN` |
| Failed login | `app/includes/auth.php`, `attempt_login()` (Phase 3) | `LOGIN_FAILED`, `LOGIN_BLOCKED`, `ACCOUNT_LOCKED` |
| Access to sensitive information | `app/view_researchers.php` (new, Phase 7) - logs once per researcher row actually viewed, whether decryption succeeded or not | `VIEW_SENSITIVE` |
| Record modification | `app/update_proposal.php` (new, Phase 7) - logs every status-change attempt, success or not | `UPDATE_RECORD` |
| Record deletion | `app/delete_proposal.php` (new, Phase 7) - logs successful deletions **and** blocked attempts (trying to delete a non-Draft proposal) | `DELETE_RECORD` |
| Administrative actions | `app/admin_users.php` (new, Phase 7) - DBA activating/deactivating/unlocking accounts | `ADMIN_ACTION` |
| (Bonus, not in the brief's list but useful for Phase 10) | `app/includes/bootstrap.php`, new `require_role()` function - a role trying to open a page it isn't permitted to use | `ACCESS_DENIED` |

All of these call the same `audit()` function written in Phase 3 (`app/includes/bootstrap.php`) - nothing new was invented for *how* logging works, Phase 7 only adds the missing *call sites* the brief asks for.

## 3. The five questions, and which column answers each

| Question | `audit_log` column |
|---|---|
| Who performed the activity? | `user_id` (the actual account, not trustable from the client) and `username` (a readable copy, kept even if the account is later deleted) |
| What action was performed? | `action` (e.g. `VIEW_SENSITIVE`, `DELETE_RECORD`) plus `details` for extra context (e.g. `action=deactivate`, `set status = Approved`) |
| When did it occur? | `created_at` (database-assigned timestamp - the app never sends a client-supplied time, so it can't be forged) |
| Which resource was affected? | `resource` - deliberately written as `table:id` (e.g. `proposals:3`, `users:7`, `researchers:2`) so one column identifies the exact row, not just the table |
| Was the operation successful? | `success` (boolean) - **critically, failed/blocked attempts are logged too**, not only successes. A blocked deletion or a denied page access is itself security-relevant evidence |

## 4. Demonstrating detection, not just collection
`app/audit_log.php` (Auditor/DBA only) runs two live queries against `audit_log`, also saved as reusable SQL in `sql/07_audit_queries.sql`:

1. **Brute-force detection** - groups `LOGIN_FAILED` events by username, flags any username with 3+ failures in the last 24 hours. This is the same signal the Phase 3 account-lockout feature reacts to automatically; here we show it can also be *investigated after the fact* from the log alone.
2. **Unusual privileged activity** - groups `VIEW_SENSITIVE`, `ADMIN_ACTION`, and `DELETE_RECORD` events by username, so an auditor can see at a glance which accounts touched sensitive data, performed admin actions, or deleted records recently, and how often.

`sql/07_audit_queries.sql` adds four more reference queries beyond the two shown in the UI: full history for one account, full history for one resource, a list of every blocked/denied attempt, and an off-hours (00:00-06:00) activity check - these are the kind of queries Phase 10's incident investigation will reuse directly.

## 5. How to generate evidence for this phase
1. Log in as `app_officer` and change a proposal's status with `update_proposal.php` -> `P7-01-update-record.png`.
2. Try to delete a non-Draft proposal with `delete_proposal.php`, see it blocked -> `P7-02-delete-blocked.png`. Then delete an actual Draft one successfully -> `P7-03-delete-success.png`.
3. Log in as `app_dba` (or `app_finance`) and open `view_researchers.php` -> `P7-04-view-sensitive.png`.
4. Log in as `app_dba` and deactivate/unlock a test account via `admin_users.php` -> `P7-05-admin-action.png`.
5. Deliberately fail a login 3 times for one test account, then log in as `app_auditor` and open `audit_log.php` -> `P7-06-detection-bruteforce.png` showing that account under "Detection 1".
6. Screenshot the full recent-log table on the same page -> `P7-07-audit-log-raw.png`, and run at least one query from `07_audit_queries.sql` directly in phpMyAdmin/CLI as `app_auditor` -> `P7-08-sql-query-evidence.png`.

What each screenshot demonstrates (brief rule: "screenshots alone are not sufficient evidence"):
- `P7-01` to `P7-05` prove each of the five required categories is actually being written, not just designed on paper.
- `P7-02` specifically proves **blocked attempts are logged**, which matters because an attacker's unsuccessful attempts are often the most important thing an investigator needs.
- `P7-06` to `P7-08` prove the log is *usable* for detection, per the brief's explicit requirement to "demonstrate how the collected information could be used to detect or investigate suspicious activity" - a table of rows nobody ever queries would not satisfy this.

## 6. Known limitations (being honest, as in every prior phase)
- Detection here is **manual/on-demand** (an auditor runs a query or opens a page). There is no automated alerting (e.g. an email or dashboard warning fired the moment a threshold is crossed) - that would be the next step in a production system, and is explicitly out of scope for a course lab.
- The "off-hours" and "3 failures in 24h" thresholds are illustrative, not tuned against real traffic volume; a production system would calibrate these against a baseline.
- `audit_log` itself is only protected by Phase 2's RBAC (only `role_auditor`/`role_dba` can read it, and nobody but the app's own `INSERT`-only path can write to it in normal operation) - it is not yet write-once/tamper-evident (e.g. no append-only storage, no hash chaining of log rows). A sufficiently privileged account (DBA) could in theory alter past log rows directly in the database; this is flagged here rather than solved, as a realistic limitation of a single-VM lab setup.
- `view_researchers.php` shows **all** researchers to any allowed role for demo simplicity, rather than scoping by "only researchers on your own active grants" - a real system would add that narrower scoping on top of the role check.
