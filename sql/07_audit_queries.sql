-- Phase 7: Database Auditing and Monitoring
-- Reference queries you ran (and can re-run as evidence) against the audit_log
-- table to show detection, not just collection, of suspicious activity.
-- Run these as role_auditor / app_auditor (read-only), never as root.

-- 1. Brute-force detection: same username, 3+ failed logins in 24h.
SELECT username, COUNT(*) AS failures, MIN(event_time) AS first_attempt, MAX(event_time) AS last_attempt
  FROM audit_log
 WHERE action = 'LOGIN_FAILED' AND event_time >= NOW() - INTERVAL 1 DAY
 GROUP BY username
HAVING COUNT(*) >= 3
 ORDER BY failures DESC;

-- 2. Unusual privileged activity: sensitive-data views, admin actions, or
--    deletions by any one account in the last 24h.
SELECT username, action, COUNT(*) AS event_count, MAX(event_time) AS last_seen
  FROM audit_log
 WHERE action IN ('VIEW_SENSITIVE', 'ADMIN_ACTION', 'DELETE_RECORD')
   AND event_time >= NOW() - INTERVAL 1 DAY
 GROUP BY username, action
HAVING COUNT(*) >= 1
 ORDER BY event_count DESC;

-- 3. Full history for one specific account (investigation drill-down:
--    "what did this user do, in order?"). Replace the username before running.
SELECT event_time, action, resource, success, ip_address, details
  FROM audit_log
 WHERE username = 'app_officer'
 ORDER BY event_time ASC;

-- 4. Everything that happened to one specific resource (e.g. one proposal),
--    across every user who touched it.
SELECT event_time, username, action, success, details
  FROM audit_log
 WHERE resource = 'proposals:1'
 ORDER BY event_time ASC;

-- 5. Attempts that were blocked / denied (failed logins, blocked deletions,
--    role-based access denials) - the "something was tried and stopped" view.
SELECT event_time, username, action, resource, details
  FROM audit_log
 WHERE success = 0
 ORDER BY event_time DESC
 LIMIT 100;

-- 6. Activity outside normal business hours (00:00-06:00), a classic
--    monitoring heuristic for privileged/administrative actions.
SELECT event_time, username, action, resource, details
  FROM audit_log
 WHERE action IN ('ADMIN_ACTION', 'VIEW_SENSITIVE', 'DELETE_RECORD')
   AND HOUR(event_time) BETWEEN 0 AND 6
 ORDER BY event_time DESC;
