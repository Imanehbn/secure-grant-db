-- Phase 7: app_login needs a few more privileges, because until now the
-- live application only ever touched the `users` / `app_roles` tables
-- (login). The new Phase 7 pages are the first part of the app that reads
-- or changes `proposals`, `researchers` and `users` beyond login itself.
--
-- This is still least-privilege: only the specific actions the app code
-- actually performs are granted, nothing broader (no DELETE on researchers,
-- no access to budget_lines/expenditures, which nothing in the app uses yet;
-- and the users UPDATE grant is column-level, matching the column-level
-- privilege design from Phase 2 - app_login still cannot change, say,
-- password_hash or role_id through this grant).
--
-- Run this as root (phpMyAdmin SQL tab, logged in as root; or the mysql CLI).

GRANT SELECT, UPDATE, DELETE ON grantdb.proposals TO 'app_login'@'localhost';
GRANT SELECT ON grantdb.researchers TO 'app_login'@'localhost';
GRANT UPDATE (is_active, locked_until, failed_attempts) ON grantdb.users TO 'app_login'@'localhost';
GRANT SELECT ON grantdb.audit_log TO 'app_login'@'localhost';

FLUSH PRIVILEGES;

-- Verify it worked:
SHOW GRANTS FOR 'app_login'@'localhost';
