-- Phase 8: repair script after discovering mysql.db corruption
-- (mysqlcheck --auto-repair wiped the corrupted mysql.db table from 5 rows
-- to 0, which silently deleted role_dba's database-wide privilege grant).
--
-- This re-runs ONLY the role/privilege parts of sql/02_users_roles.sql -
-- it deliberately SKIPS the CREATE OR REPLACE USER ... IDENTIFIED BY lines,
-- so none of your real passwords are touched or reset.
--
-- Run as root in phpMyAdmin's SQL tab, with grantdb selected.

USE grantdb;

-- Roles (idempotent - CREATE ROLE IF NOT EXISTS does nothing if they already exist)
CREATE ROLE IF NOT EXISTS role_dba;
CREATE ROLE IF NOT EXISTS role_grants_officer;
CREATE ROLE IF NOT EXISTS role_pi;
CREATE ROLE IF NOT EXISTS role_reviewer;
CREATE ROLE IF NOT EXISTS role_finance;
CREATE ROLE IF NOT EXISTS role_auditor;
CREATE ROLE IF NOT EXISTS role_app;

-- Stored procedure (mysql.proc also showed corruption during the repair,
-- so recreate this to be safe)
DROP PROCEDURE IF EXISTS sp_submit_proposal;
DELIMITER //
CREATE PROCEDURE sp_submit_proposal(IN p_proposal_id INT UNSIGNED)
SQL SECURITY DEFINER
BEGIN
    UPDATE proposals
       SET status = 'Submitted', submitted_at = NOW()
     WHERE proposal_id = p_proposal_id
       AND status = 'Draft';
END //
DELIMITER ;

-- Privileges granted to roles (this is what mysql.db lost)
GRANT ALL PRIVILEGES ON grantdb.* TO role_dba WITH GRANT OPTION;

GRANT SELECT (researcher_id, user_id, department_id, full_name, academic_rank, orcid)
      ON grantdb.researchers TO role_grants_officer;
GRANT SELECT, INSERT, UPDATE ON grantdb.departments      TO role_grants_officer;
GRANT SELECT, INSERT, UPDATE ON grantdb.funding_agencies TO role_grants_officer;
GRANT SELECT ON grantdb.proposals TO role_grants_officer;
GRANT UPDATE (status)         ON grantdb.proposals TO role_grants_officer;
GRANT SELECT ON grantdb.proposal_reviews TO role_grants_officer;
GRANT SELECT, INSERT, UPDATE ON grantdb.grants       TO role_grants_officer;
GRANT SELECT, INSERT, UPDATE ON grantdb.budget_lines TO role_grants_officer;
GRANT SELECT ON grantdb.expenditures TO role_grants_officer;

GRANT SELECT (researcher_id, user_id, department_id, full_name, academic_rank, orcid)
      ON grantdb.researchers TO role_pi;
GRANT SELECT ON grantdb.departments      TO role_pi;
GRANT SELECT ON grantdb.funding_agencies TO role_pi;
GRANT SELECT ON grantdb.proposals        TO role_pi;
GRANT INSERT (title, abstract, pi_id, agency_id, requested_amount)
      ON grantdb.proposals TO role_pi;
GRANT UPDATE (title, abstract, requested_amount)
      ON grantdb.proposals TO role_pi;
GRANT EXECUTE ON PROCEDURE grantdb.sp_submit_proposal TO role_pi;
GRANT SELECT ON grantdb.grants       TO role_pi;
GRANT SELECT ON grantdb.budget_lines TO role_pi;
GRANT SELECT ON grantdb.expenditures TO role_pi;

GRANT SELECT (proposal_id, title, abstract, agency_id, requested_amount, status, submitted_at)
      ON grantdb.proposals TO role_reviewer;
GRANT SELECT ON grantdb.proposal_reviews TO role_reviewer;
GRANT INSERT (proposal_id, reviewer_id, score, comments)
      ON grantdb.proposal_reviews TO role_reviewer;
GRANT UPDATE (score, comments)
      ON grantdb.proposal_reviews TO role_reviewer;

GRANT SELECT (researcher_id, full_name, bank_account_enc)
      ON grantdb.researchers TO role_finance;
GRANT SELECT ON grantdb.grants       TO role_finance;
GRANT SELECT ON grantdb.budget_lines TO role_finance;
GRANT SELECT, INSERT ON grantdb.expenditures TO role_finance;

GRANT SELECT ON grantdb.audit_log    TO role_auditor;
GRANT SELECT ON grantdb.grants       TO role_auditor;
GRANT SELECT ON grantdb.budget_lines TO role_auditor;
GRANT SELECT ON grantdb.expenditures TO role_auditor;

GRANT SELECT (user_id, username, password_hash, role_id, email, is_active,
              failed_attempts, locked_until, last_login)
      ON grantdb.users TO role_app;
GRANT UPDATE (failed_attempts, locked_until, last_login)
      ON grantdb.users TO role_app;
GRANT SELECT ON grantdb.app_roles TO role_app;
GRANT INSERT ON grantdb.audit_log TO role_app;

-- Role assignment to existing users (no passwords touched)
GRANT role_dba            TO 'dba_admin'@'localhost';
GRANT role_grants_officer TO 'grants_officer1'@'localhost';
GRANT role_pi             TO 'pi_user1'@'localhost';
GRANT role_reviewer       TO 'reviewer1'@'localhost';
GRANT role_finance        TO 'finance1'@'localhost';
GRANT role_auditor        TO 'auditor1'@'localhost';
GRANT role_app            TO 'app_login'@'localhost';

SET DEFAULT ROLE role_dba            FOR 'dba_admin'@'localhost';
SET DEFAULT ROLE role_grants_officer FOR 'grants_officer1'@'localhost';
SET DEFAULT ROLE role_pi             FOR 'pi_user1'@'localhost';
SET DEFAULT ROLE role_reviewer       FOR 'reviewer1'@'localhost';
SET DEFAULT ROLE role_finance        FOR 'finance1'@'localhost';
SET DEFAULT ROLE role_auditor        FOR 'auditor1'@'localhost';
SET DEFAULT ROLE role_app            FOR 'app_login'@'localhost';

FLUSH PRIVILEGES;

-- Verify:
SHOW GRANTS FOR 'role_dba';
