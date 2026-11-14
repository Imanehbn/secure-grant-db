# Final Database Security Assessment

This assessment answers the brief's 9 required questions about the completed system, drawing on the evidence and decisions documented across Phases 2-10. Each answer states the actual current status, points to the specific evidence behind it, and names any remaining limitation honestly rather than overstating completeness.

## 1. Authentication: Are users properly authenticated?
**Status: Yes, with one documented gap.**
Every application account authenticates through `login.php` against `app_login`'s scoped database access, using bcrypt password hashing (`$2y$10$...`), prepared statements, CSRF tokens on the login form, and secure session handling (`HttpOnly`, `SameSite=Strict` cookies). Failed authentication is rate-limited: 5 wrong passwords lock an account for 15 minutes, enforced in the database itself (not just the page), so it can't be bypassed by changing the browser. The system gives no information that would let an attacker tell a wrong password apart from an unknown username (Phase 3, tests 2-3).

**Gap:** no multi-factor authentication exists for any account, including the DBA role with the broadest reach. Phase 10's incident investigation specifically identified this as a real exposure: if a privileged account's password alone were compromised, nothing else would stop misuse.

## 2. Authorization: Can users access only the resources required for their responsibilities?
**Status: Yes.**
Seven roles (`role_dba`, `role_grants_officer`, `role_pi`, `role_reviewer`, `role_finance`, `role_auditor`, `role_app`) each carry only the GRANTs their responsibilities require, enforced at the database level via MariaDB roles, not just in application code. Phase 2's tests proved this directly: a PI gets `ERROR 1143` trying to read `bank_account_enc`, `ERROR 1142` trying to touch `users` or `DELETE FROM proposals`; a reviewer gets `ERROR 1143` on `proposals.pi_id` (enforcing blind review); an auditor gets `ERROR 1142` on `INSERT INTO audit_log` (a read-only auditor can't tamper with the evidence it's meant to review). Because these are database-level privileges, they hold even if the PHP application code had a bug — the database itself is the enforcement point, not just a trusted layer above it.

## 3. Least Privilege: Have unnecessary privileges been removed?
**Status: Yes, verified directly in Phase 9.**
`app_login` (the account the real application actually connects as) was directly checked via `SHOW GRANTS` and shown to hold only specific column/table grants — nowhere close to `root`'s `ALL PRIVILEGES ON *.*`. Phase 9 also removed every account that didn't need to exist: the three passwordless root accounts were reduced to one authenticated `root@localhost`, and the default `pma` and `labuser` accounts were removed entirely. The one deliberate exception — `app_vuln`'s broad privileges — is documented and justified as evidence infrastructure for Phases 4-5, isolated from the production path, not a production account.

## 4. Application Security: Has SQL Injection been appropriately mitigated?
**Status: Yes, demonstrated with a working exploit and its fix, not just a claim.**
Phase 4 proved the vulnerability was real before any fix existed: an always-true `WHERE` bypass leaked confidential draft proposals, and a `UNION SELECT` leaked every account's username and password hash. Phase 5 then re-ran the identical payloads against the fixed code and showed all three independent layers holding: prepared statements (so injected SQL is only ever treated as literal search text), input validation (rejecting the characters the payloads depend on), and the least-privileged `app_search` account (which couldn't reach the `users` table even if the other two layers failed). Demonstrating that three independent layers would each catch the same attack is stronger evidence than showing one fix working once.

## 5. Data Protection: Is sensitive information appropriately protected?
**Status: Yes, with one accepted limitation.**
Restricted-classification fields (national ID, phone, bank account) are encrypted with application-level AES-256-GCM (Phase 6), not MySQL's built-in `AES_ENCRYPT`, specifically so the key never appears in SQL query text or logs. Phase 6 proved this wasn't just RBAC hiding the data: querying the raw column as root (`SELECT HEX(national_id_enc)`) shows only ciphertext. The key itself lives outside both web-servable folders, excluded from git, and (Phase 9) its filesystem permissions are restricted to the file owner, SYSTEM, and Administrators only.

**Limitation:** data in transit is still HTTP only, with no database TLS — flagged honestly since Phase 3 and not resolved by project end, a reasonable scope decision for a single lab VM but a real gap for any production use.

## 6. Auditing and Monitoring: Can important security activities be identified and traced?
**Status: Yes, demonstrated against a real, freshly-produced incident, not only test data.**
`audit_log` (built in Phase 3, extended in Phase 7) answers all 5 required questions — who, what, when, which resource, was it successful — for every login, sensitive-data view, record modification, deletion, and administrative action. Phase 7 proved detection works, not just collection: a deliberately-triggered brute-force attempt was automatically flagged by a grouping query. Phase 10 then validated this against a fresh, two-part simulated incident and additionally cross-checked the log against the live `users` table state, confirming the log's claims were independently corroborated, not self-referential.

**Limitation:** detection is manual (someone has to open the page or run the query); `audit_log` itself is not tamper-evident against a sufficiently privileged account, since `role_dba` has `ALL PRIVILEGES` and could in theory alter its own history — both documented as real gaps by Phase 10's own investigation, not discovered independently of it.

## 7. Backup and Recovery: Can the database be successfully recovered following data loss?
**Status: Yes, proven with a real simulated loss and byte-for-byte verification, including two genuine infrastructure problems found and fixed along the way.**
Phase 8 didn't just show a backup file existing (which the brief explicitly says isn't sufficient) — it dropped a real table (`researchers`, bypassing the foreign-key safeguard that initially blocked it), confirmed the application actually broke as a result, restored from `mysqldump`, and verified the recovered data decrypted correctly and matched byte-for-byte. Two real problems were found and fixed in the process rather than hidden: a PowerShell text-pipe corrupting binary ciphertext (fixed with `--hex-blob`), and a genuine MariaDB system-table corruption that silently deleted `role_dba`'s own privilege grant (fixed with a targeted repair script that didn't touch any passwords). Phase 9 then closed the backup-protection gap Phase 8 flagged, encrypting the backup file itself with 7-Zip AES-256 and proving the encryption was real (wrong password rejected, correct password succeeds).

**Limitation:** manual/on-demand only, full-database restore (not table-level), and still stored locally — accepted as reasonable for a single lab VM.

## 8. Hardening: Has the attack surface been reduced?
**Status: Yes, across all 12 items identified in the Phase 1 baseline.**
Default/passwordless accounts removed, unnecessary `test` database dropped, network exposure restricted to loopback at two independent layers (`bind-address` + firewall rule), only the 2 required services confirmed running, file permissions verified on the most sensitive files, logging reviewed with a documented least-exposure decision, and backup files now encrypted. The one item not fully remediated — outdated MariaDB/PHP/Apache versions — was investigated honestly (specific CVEs and EOL dates identified) and given a documented remediation plan rather than either hidden or rushed into a risky late-stage upgrade; the professor was consulted directly on whether this approach is acceptable.

## 9. Incident Investigation: Can available evidence support an investigation of suspicious activity?
**Status: Yes, demonstrated end-to-end on a real, freshly-produced incident.**
Phase 10 ran an actual two-part simulated incident (unauthorized access attempts + unusual privileged-account activity, matching the brief's own example) and then investigated it using only the evidence the system captured — the audit log, its detection queries, direct SQL, and the live database state — answering all 7 of the brief's required investigation questions with a full timeline. The investigation also honestly flagged a real artifact in its own evidence (three log entries only 4ms apart, too fast to be a human reading each record) rather than overstating what the data proved.

## Summary
| Area | Status |
|---|---|
| Authentication | Solid; no MFA |
| Authorization | Solid |
| Least Privilege | Solid, verified directly |
| Application Security (SQLi) | Solid, proven with working exploit + fix |
| Data Protection | Solid; no transport encryption |
| Auditing and Monitoring | Solid; manual detection, log not tamper-evident |
| Backup and Recovery | Solid; manual, local-only |
| Hardening | Solid across 11/12 items; patching documented not executed |
| Incident Investigation | Solid, proven end-to-end |

Across all 9 areas, every claim in this assessment is backed by evidence captured during the project (screenshots, SQL output, or reproducible steps) rather than asserted without demonstration — consistent with this project's approach throughout of showing real, working controls and honestly documenting their limitations rather than presenting an idealized system.
