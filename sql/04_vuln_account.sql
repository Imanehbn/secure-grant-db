-- =====================================================================
-- GrantDB - Phase 4: account used ONLY by the deliberately vulnerable page
--
-- INTENTIONALLY OVER-PRIVILEGED (SELECT on every table of grantdb).
-- This is the "weak application account" the brief asks for. It is what
-- turns a SQL injection in one search page into a leak of the whole
-- database. Phase 5 drops this account and replaces it with a properly
-- scoped, least-privileged one.
--
-- BEFORE RUNNING: replace CHANGE_ME_vuln with a generated password in a
-- LOCAL copy named 04_vuln_account.local.sql (ignored by Git, same pattern
-- as Phase 2). Never commit a real password.
-- =====================================================================

CREATE OR REPLACE USER 'app_vuln'@'localhost' IDENTIFIED BY 'CHANGE_ME_vuln';
GRANT SELECT ON grantdb.* TO 'app_vuln'@'localhost';
FLUSH PRIVILEGES;
