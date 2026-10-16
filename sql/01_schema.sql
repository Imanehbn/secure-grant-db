-- =====================================================================
-- University Research Grant Management System (GrantDB)
-- Phase 1 - Database schema (MySQL 8.0+ / MariaDB 10.5+)
-- Run as a DBA account:  mysql -u root -p < 01_schema.sql
-- =====================================================================

DROP DATABASE IF EXISTS grantdb;
CREATE DATABASE grantdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE grantdb;

-- ---------------------------------------------------------------------
-- Reference tables
-- ---------------------------------------------------------------------
CREATE TABLE departments (
    department_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(100) NOT NULL UNIQUE,
    faculty       VARCHAR(100) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE funding_agencies (
    agency_id     INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(150) NOT NULL UNIQUE,
    country       VARCHAR(60)  NOT NULL,
    contact_email VARCHAR(120) NULL
) ENGINE=InnoDB;

-- Application-level roles (mapped to database roles in Phase 2)
CREATE TABLE app_roles (
    role_id     TINYINT UNSIGNED PRIMARY KEY,
    role_name   VARCHAR(30)  NOT NULL UNIQUE,
    description VARCHAR(255) NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Identity and authentication
-- ---------------------------------------------------------------------
CREATE TABLE users (
    user_id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(50)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,          -- bcrypt/argon2 hash, never plaintext
    role_id         TINYINT UNSIGNED NOT NULL,
    email           VARCHAR(120) NOT NULL UNIQUE,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until    DATETIME     NULL,
    last_login      DATETIME     NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES app_roles(role_id)
) ENGINE=InnoDB;

CREATE TABLE researchers (
    researcher_id    INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id          INT UNSIGNED NOT NULL UNIQUE,
    department_id    INT UNSIGNED NOT NULL,
    full_name        VARCHAR(120) NOT NULL,
    academic_rank    ENUM('Lecturer','Senior Lecturer','Associate Professor','Professor') NOT NULL,
    orcid            VARCHAR(19)  NULL,
    -- Sensitive fields stored encrypted (AES, see Phase 6)
    national_id_enc  VARBINARY(255) NOT NULL,
    phone_enc        VARBINARY(255) NULL,
    bank_account_enc VARBINARY(255) NULL,
    CONSTRAINT fk_res_user FOREIGN KEY (user_id)       REFERENCES users(user_id),
    CONSTRAINT fk_res_dept FOREIGN KEY (department_id) REFERENCES departments(department_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Grant lifecycle: proposal -> review -> grant -> budget -> spending
-- ---------------------------------------------------------------------
CREATE TABLE proposals (
    proposal_id      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    title            VARCHAR(200) NOT NULL,
    abstract         TEXT         NOT NULL,
    pi_id            INT UNSIGNED NOT NULL,          -- principal investigator
    agency_id        INT UNSIGNED NOT NULL,
    requested_amount DECIMAL(12,2) NOT NULL CHECK (requested_amount > 0),
    status           ENUM('Draft','Submitted','Under Review','Approved','Rejected')
                     NOT NULL DEFAULT 'Draft',
    submitted_at     DATETIME NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_prop_pi     FOREIGN KEY (pi_id)     REFERENCES researchers(researcher_id),
    CONSTRAINT fk_prop_agency FOREIGN KEY (agency_id) REFERENCES funding_agencies(agency_id)
) ENGINE=InnoDB;

CREATE TABLE proposal_reviews (
    review_id    INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    proposal_id  INT UNSIGNED NOT NULL,
    reviewer_id  INT UNSIGNED NOT NULL,              -- users.user_id with Reviewer role
    score        TINYINT UNSIGNED NOT NULL CHECK (score BETWEEN 0 AND 10),
    comments     TEXT NULL,
    reviewed_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_one_review (proposal_id, reviewer_id),
    CONSTRAINT fk_rev_prop FOREIGN KEY (proposal_id) REFERENCES proposals(proposal_id),
    CONSTRAINT fk_rev_user FOREIGN KEY (reviewer_id) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE grants (
    grant_id     INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    proposal_id  INT UNSIGNED NOT NULL UNIQUE,
    award_amount DECIMAL(12,2) NOT NULL CHECK (award_amount > 0),
    start_date   DATE NOT NULL,
    end_date     DATE NOT NULL,
    status       ENUM('Active','Closed','Suspended') NOT NULL DEFAULT 'Active',
    approved_by  INT UNSIGNED NOT NULL,              -- users.user_id (Grants Officer)
    CONSTRAINT chk_grant_dates CHECK (end_date > start_date),
    CONSTRAINT fk_grant_prop FOREIGN KEY (proposal_id) REFERENCES proposals(proposal_id),
    CONSTRAINT fk_grant_appr FOREIGN KEY (approved_by) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE budget_lines (
    line_id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    grant_id         INT UNSIGNED NOT NULL,
    category         ENUM('Equipment','Travel','Personnel','Consumables','Overhead') NOT NULL,
    allocated_amount DECIMAL(12,2) NOT NULL CHECK (allocated_amount >= 0),
    UNIQUE KEY uq_grant_category (grant_id, category),
    CONSTRAINT fk_bl_grant FOREIGN KEY (grant_id) REFERENCES grants(grant_id)
) ENGINE=InnoDB;

CREATE TABLE expenditures (
    expenditure_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    line_id        INT UNSIGNED NOT NULL,
    amount         DECIMAL(12,2) NOT NULL CHECK (amount > 0),
    description    VARCHAR(255) NOT NULL,
    spent_on       DATE NOT NULL,
    recorded_by    INT UNSIGNED NOT NULL,            -- users.user_id (Finance Officer)
    CONSTRAINT fk_exp_line FOREIGN KEY (line_id)     REFERENCES budget_lines(line_id),
    CONSTRAINT fk_exp_user FOREIGN KEY (recorded_by) REFERENCES users(user_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Security audit trail (populated by the application and by triggers, Phase 7)
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    audit_id    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_time  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    user_id     INT UNSIGNED NULL,                   -- NULL for unknown user (failed login)
    username    VARCHAR(50)  NULL,
    action      VARCHAR(40)  NOT NULL,               -- LOGIN, LOGIN_FAILED, SELECT_SENSITIVE, UPDATE, DELETE, ...
    resource    VARCHAR(60)  NOT NULL,               -- table or page name
    resource_id VARCHAR(40)  NULL,
    success     BOOLEAN      NOT NULL,
    ip_address  VARCHAR(45)  NULL,
    details     VARCHAR(500) NULL,
    INDEX idx_audit_time (event_time),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_action (action)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Seed reference data
-- ---------------------------------------------------------------------
INSERT INTO app_roles (role_id, role_name, description) VALUES
 (1, 'DBA',            'Database administrator'),
 (2, 'GrantsOfficer',  'Research office: manages proposals and awards'),
 (3, 'PI',             'Principal investigator / researcher'),
 (4, 'Reviewer',       'Evaluation committee member'),
 (5, 'FinanceOfficer', 'Records and monitors expenditures'),
 (6, 'Auditor',        'Read-only access to audit logs');
