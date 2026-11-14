# Secure Grant Database (GrantDB)

University Research Grant Management System, built for the Database Security course (5th year Engineering in Cybersecurity, Dr. Abdulganiyu O. Harazeem).

**Status: all 10 phases complete** (Database Design, RBAC/Least Privilege, Authentication, Vulnerability Analysis, SQL Injection Remediation, Sensitive Data Protection, Auditing/Monitoring, Backup/Recovery, Hardening, Incident Investigation), plus the Final Database Security Assessment.

Stack: Windows 11, XAMPP (Apache, MariaDB 10.4.32, PHP 8.2.12), phpMyAdmin.

## Structure
- `sql/` — database creation, role/privilege, and repair scripts (run in order, see below)
- `app/` — the secure production application (PHP)
- `app_vulnerable/` — the deliberately vulnerable component used for Phase 4/5 (isolated, `localhost`-only, never deployed elsewhere)
- `keys/` — encryption key (git-ignored; `encryption.key.example.php` is the committed template)
- `backup/` — local backups (git-ignored entirely — see `docs/phase9_hardening.md` item 12 for why)
- `tools/` — helper scripts (key generation, encryption migration, decrypt verification)
- `docs/` — one write-up per phase, the Final Security Assessment, and `docs/evidence/` (all screenshots referenced in the write-ups)

## Setup / reproduction steps
1. Install XAMPP (Apache + MariaDB + PHP). Start Apache and MySQL.
2. In phpMyAdmin (or via the `mysql` CLI), run the SQL scripts in `sql/` **in numeric order** (e.g. `01_schema...sql`, then `02_users_roles.sql`, etc.). Before running `02_users_roles.sql`, copy it to `02_users_roles.local.sql` and replace every `CHANGE_ME_...` placeholder with your own strong password — this local copy is git-ignored and never committed.
3. Copy `keys/encryption.key.example.php` to `keys/encryption.key.php` and run `tools/generate_key.php` to fill it with a real random 32-byte key (this file is git-ignored; never commit a real key).
4. Copy `app/config.example.php` (if present) to `app/config.php` and fill in the database credentials matching the accounts created in step 2.
5. Copy `app/` to your web server's document root (e.g. `C:\xampp\htdocs\grantdb`).
6. Seed sample data with `sql/04_sample_data.sql`, then run `tools/migrate_encrypt_researchers.php` once to encrypt the researcher records' sensitive columns.
7. Visit `http://localhost/grantdb/login.php`. Log in with any of the role accounts created in step 2 (credentials are generated locally in step 2 and are not committed anywhere in this repo).

Each phase's write-up in `docs/` documents the exact commands, decisions, and evidence for that part of the system, and can be used to reproduce or verify any individual control (e.g. `docs/phase8_backup_recovery.md` for the backup/restore procedure, `docs/phase9_hardening.md` for every hardening change and its justification).

## Documentation map
| Phase | Document |
|---|---|
| 1 — Design & Security Analysis | `docs/phase1_design_security_analysis.md` |
| 2 — Users, RBAC, Least Privilege | `docs/phase2_rbac.md` |
| 3 — Secure Authentication | `docs/phase3_authentication.md` |
| 4 — Controlled Vulnerability Analysis | `docs/phase4_vulnerability_analysis.md` |
| 5 — SQL Injection Prevention | `docs/phase5_sql_injection_prevention.md` |
| 6 — Sensitive Data Protection | `docs/phase6_data_protection.md` |
| 7 — Auditing and Monitoring | `docs/phase7_auditing_monitoring.md` |
| 8 — Backup and Recovery | `docs/phase8_backup_recovery.md` |
| 9 — Database Hardening | `docs/phase9_hardening.md` |
| 10 — Incident Investigation | `docs/phase10_incident_investigation.md` |
| Final Security Assessment | `docs/final_security_assessment.md` |
| Running log of tests and findings | `docs/notes.md` |
