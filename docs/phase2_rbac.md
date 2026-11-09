# Phase 2: Database Users, RBAC and Least Privilege

## 1. Design decisions
- Privileges are granted to **roles**, never directly to users. Adding a person means assigning a role, not re-writing privileges.
- One database account per role for the lab (`pi_user1`, `reviewer1`, ...). After login, the application connects with the account that matches the user's role, so the **database itself** enforces the limits, not only the PHP code.
- `app_login` is a separate service account used only to authenticate users and write audit events. It cannot read any business table.
- `dba_admin` has full rights on `grantdb` only, not on the whole server.
- Column-level privileges hide sensitive columns (national ID, phone, bank account, PI identity).

## 2. Access-control matrix
S = SELECT, I = INSERT, U = UPDATE, D = DELETE, X = EXECUTE, (cols) = limited columns, - = no access.

| Table | DBA | Grants Officer | PI | Reviewer | Finance | Auditor | app_login |
|---|---|---|---|---|---|---|---|
| users | ALL | - | - | - | - | - | S, U(failed_attempts, locked_until, last_login) |
| app_roles | ALL | - | - | - | - | - | S |
| researchers | ALL | S(non-sensitive cols) | S(non-sensitive cols) | - | S(id, name, bank) | - | - |
| departments, funding_agencies | ALL | S, I, U | S | - | - | - | - |
| proposals | ALL | S, U(status) | S, I(5 cols), U(title, abstract, amount), X(submit) | S(no pi_id) | - | - | - |
| proposal_reviews | ALL | S | - | S, I, U(score, comments) | - | - | - |
| grants | ALL | S, I, U | S | - | S | S | - |
| budget_lines | ALL | S, I, U | S | - | S | S | - |
| expenditures | ALL | S | S | - | S, I | S | - |
| audit_log | ALL | - | - | - | - | S | I |

No role other than the DBA has DELETE on any table.

## 3. Least-privilege justifications
- **PI cannot set `status`:** otherwise a researcher could mark their own proposal Approved. Submission goes through `sp_submit_proposal`, which can only move Draft to Submitted.
- **Reviewer cannot read `pi_id`:** double-blind review protects against bias and pressure.
- **Officer cannot read national ID or bank data:** not needed to manage proposals; limits damage if the account is stolen.
- **Finance reads bank data but cannot change grants:** separation of duties between awarding money and paying it.
- **Auditor is read-only:** an auditor who can edit records cannot be trusted as an auditor.
- **`app_login` sees no business data:** an SQL injection in the login page cannot reach proposals or grants.

## 4. Known limitations (be ready to discuss)
- MariaDB has no row-level security. "A PI sees only their own proposals" is enforced by the application (a `WHERE pi_id = ?` with a prepared statement, Phases 3 and 5).
- The DBA role can still modify `audit_log`. This is addressed in Phase 7 (triggers and a separate audit procedure).
- `root` and the other default accounts still exist. They are handled in Phase 9.

## 5. Privilege tests
Run each command in Command Prompt. It asks for the password of that user.
Prefix: `C:\xampp\mysql\bin\mysql.exe -u USER -p grantdb -e "SQL"`

| # | USER | SQL | Expected result |
|---|---|---|---|
| 1 | pi_user1 | `SELECT proposal_id, title FROM proposals;` | Allowed (empty) |
| 2 | pi_user1 | `SELECT bank_account_enc FROM researchers;` | ERROR 1143 column denied |
| 3 | pi_user1 | `SELECT * FROM users;` | ERROR 1142 command denied |
| 4 | pi_user1 | `UPDATE proposals SET status='Approved';` | ERROR 1143 column denied |
| 5 | pi_user1 | `DELETE FROM proposals;` | ERROR 1142 command denied |
| 6 | reviewer1 | `SELECT pi_id FROM proposals;` | ERROR 1143 column denied |
| 7 | reviewer1 | `SELECT * FROM grants;` | ERROR 1142 command denied |
| 8 | grants_officer1 | `SELECT national_id_enc FROM researchers;` | ERROR 1143 column denied |
| 9 | grants_officer1 | `DELETE FROM grants;` | ERROR 1142 command denied |
| 10 | finance1 | `SELECT bank_account_enc FROM researchers;` | Allowed (empty) |
| 11 | finance1 | `UPDATE grants SET award_amount=1;` | ERROR 1142 command denied |
| 12 | auditor1 | `SELECT * FROM audit_log;` | Allowed (empty) |
| 13 | auditor1 | `INSERT INTO audit_log (action,resource,success) VALUES ('x','y',1);` | ERROR 1142 command denied |
| 14 | app_login | `SELECT username, password_hash FROM users;` | Allowed (empty) |
| 15 | app_login | `SELECT * FROM proposals;` | ERROR 1142 command denied |

## 6. Evidence to capture (save in docs/evidence/)
- `P2-01-show-grants-role-pi.png`: `SHOW GRANTS FOR role_pi;`
- `P2-02-show-grants-user.png`: `SHOW GRANTS FOR 'pi_user1'@'localhost';`
- `P2-03` to `P2-17`: one screenshot per test above (allowed and denied)
- `P2-18-revoke-demo.png`: the GRANT / REVOKE demonstration at the end of `02_users_roles.sql`

