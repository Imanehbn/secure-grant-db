-- =====================================================================
-- GrantDB - Phase 2: database roles, users and privileges (least privilege)
-- Target: MariaDB 10.4 (roles supported since 10.0.5)
--
-- BEFORE RUNNING: replace every CHANGE_ME_... password with a strong,
-- unique one in a LOCAL copy named 02_users_roles.local.sql
-- (that file name is ignored by Git). Never commit real passwords.
--
-- Run as root from the server home page in phpMyAdmin (Import tab).
-- =====================================================================

USE grantdb;

-- ---------------------------------------------------------------------
-- 1. Roles (one per job function)
-- ---------------------------------------------------------------------
CREATE ROLE IF NOT EXISTS role_dba;
CREATE ROLE IF NOT EXISTS role_grants_officer;
CREATE ROLE IF NOT EXISTS role_pi;
CREATE ROLE IF NOT EXISTS role_reviewer;
CREATE ROLE IF NOT EXISTS role_finance;
CREATE ROLE IF NOT EXISTS role_auditor;
CREATE ROLE IF NOT EXISTS role_app;          -- application login service account

-- ---------------------------------------------------------------------
-- 2. Stored procedure: the only way a PI can submit a proposal.
--    PIs get no UPDATE on proposals.status, so they cannot set 'Approved'.
-- ---------------------------------------------------------------------
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

-- ---------------------------------------------------------------------
-- 3. Privileges granted to ROLES (never directly to users)
-- ---------------------------------------------------------------------

-- DBA: full control of grantdb only (not global)
GRANT ALL PRIVILEGES ON grantdb.* TO role_dba WITH GRANT OPTION;

-- Grants officer (research office)
GRANT SELECT (researcher_id, user_id, department_id, full_name, academic_rank, orcid)
      ON grantdb.researchers TO role_grants_officer;       -- no national ID, phone, bank
GRANT SELECT, INSERT, UPDATE ON grantdb.departments      TO role_grants_officer;
GRANT SELECT, INSERT, UPDATE ON grantdb.funding_agencies TO role_grants_officer;
GRANT SELECT ON grantdb.proposals TO role_grants_officer;
GRANT UPDATE (status)         ON grantdb.proposals TO role_grants_officer;
GRANT SELECT ON grantdb.proposal_reviews TO role_grants_officer;
GRANT SELECT, INSERT, UPDATE ON grantdb.grants       TO role_grants_officer;
GRANT SELECT, INSERT, UPDATE ON grantdb.budget_lines TO role_grants_officer;
GRANT SELECT ON grantdb.expenditures TO role_grants_officer;

-- Principal investigator
GRANT SELECT (researcher_id, user_id, department_id, full_name, academic_rank, orcid)
      ON grantdb.researchers TO role_pi;
GRANT SELECT ON grantdb.departments      TO role_pi;
GRANT SELECT ON grantdb.funding_agencies TO role_pi;
GRANT SELECT ON grantdb.proposals        TO role_pi;
GRANT INSERT (title, abstract, pi_id, agency_id, requested_amount)
      ON grantdb.proposals TO role_pi;                     -- status stays 'Draft'
GRANT UPDATE (title, abstract, requested_amount)
      ON grantdb.proposals TO role_pi;
GRANT EXECUTE ON PROCEDURE grantdb.sp_submit_proposal TO role_pi;
GRANT SELECT ON grantdb.grants       TO role_pi;
GRANT SELECT ON grantdb.budget_lines TO role_pi;
GRANT SELECT ON grantdb.expenditures TO role_pi;

-- Reviewer (double-blind: cannot see who the PI is)
GRANT SELECT (proposal_id, title, abstract, agency_id, requested_amount, status, submitted_at)
      ON grantdb.proposals TO role_reviewer;
GRANT SELECT ON grantdb.proposal_reviews TO role_reviewer;
GRANT INSERT (proposal_id, reviewer_id, score, comments)
      ON grantdb.proposal_reviews TO role_reviewer;
GRANT UPDATE (score, comments)
      ON grantdb.proposal_reviews TO role_reviewer;

-- Finance officer
GRANT SELECT (researcher_id, full_name, bank_account_enc)
      ON grantdb.researchers TO role_finance;              -- needs bank data to pay
GRANT SELECT ON grantdb.grants       TO role_finance;
GRANT SELECT ON grantdb.budget_lines TO role_finance;
GRANT SELECT, INSERT ON grantdb.expenditures TO role_finance;

-- Auditor (read-only)
GRANT SELECT ON grantdb.audit_log    TO role_auditor;
GRANT SELECT ON grantdb.grants       TO role_auditor;
GRANT SELECT ON grantdb.budget_lines TO role_auditor;
GRANT SELECT ON grantdb.expenditures TO role_auditor;

-- Application login service account (authentication only)
GRANT SELECT (user_id, username, password_hash, role_id, email, is_active,
              failed_attempts, locked_until, last_login)
      ON grantdb.users TO role_app;
GRANT UPDATE (failed_attempts, locked_until, last_login)
      ON grantdb.users TO role_app;
GRANT SELECT ON grantdb.app_roles TO role_app;
GRANT INSERT ON grantdb.audit_log TO role_app;

-- ---------------------------------------------------------------------
-- 4. Database users (one per role for the lab) and role assignment
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dba_admin'@'localhost'      IDENTIFIED BY 'CHANGE_ME_dba';
CREATE USER IF NOT EXISTS 'grants_officer1'@'localhost' IDENTIFIED BY 'CHANGE_ME_officer';
CREATE USER IF NOT EXISTS 'pi_user1'@'localhost'        IDENTIFIED BY 'CHANGE_ME_pi';
CREATE USER IF NOT EXISTS 'reviewer1'@'localhost'       IDENTIFIED BY 'CHANGE_ME_reviewer';
CREATE USER IF NOT EXISTS 'finance1'@'localhost'        IDENTIFIED BY 'CHANGE_ME_finance';
CREATE USER IF NOT EXISTS 'auditor1'@'localhost'        IDENTIFIED BY 'CHANGE_ME_auditor';
CREATE USER IF NOT EXISTS 'app_login'@'localhost'       IDENTIFIED BY 'CHANGE_ME_app';

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

-- ---------------------------------------------------------------------
-- 5. Demonstration of REVOKE (run manually and screenshot)
-- ---------------------------------------------------------------------
-- GRANT DELETE ON grantdb.grants TO role_finance;      -- mistake...
-- SHOW GRANTS FOR role_finance;
-- REVOKE DELETE ON grantdb.grants FROM role_finance;   -- ...corrected
-- SHOW GRANTS FOR role_finance;
