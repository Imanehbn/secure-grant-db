# Phase 8: Backup and Recovery

## 1. Backup procedure

Backups are created with `mysqldump`, the standard MariaDB/MySQL command-line backup tool bundled with XAMPP (`C:\xampp\mysql\bin\mysqldump.exe`). A full logical backup of the `grantdb` database is taken as root (backups must capture everything, so the most privileged account is appropriate here, unlike the application's day-to-day least-privilege accounts).

```powershell
cd C:\Users\ImaneHABBANI\Desktop\projects\secure-grant-db
mkdir backup -Force
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
& "C:\xampp\mysql\bin\mysqldump.exe" -u root --routines --triggers grantdb > "backup\grantdb_backup_$stamp.sql"
```

- `--routines` includes the `sp_submit_proposal` stored procedure from Phase 2 (a plain `mysqldump` would otherwise skip it).
- `--triggers` included for completeness, in case any were added.
- No `-p` flag is used because the lab's root account has no password set (flagged as a known issue since Phase 1, to be fixed in Phase 9 hardening); if a root password is set by the time this runs, add `-p` and enter it when prompted.
- The output file is a plain `.sql` text file containing `DROP TABLE IF EXISTS` + `CREATE TABLE` + `INSERT` statements for every table, in the right order to respect foreign keys.
- `backup/*.sql` is already excluded by `.gitignore` — backups are not committed to GitHub, since they are a full copy of the database (including the AES-encrypted sensitive columns, which is fine to keep local but unnecessary to publish).

## 2. Simulated data loss

To demonstrate recovery realistically (per the brief: "a critical database table has accidentally been deleted"), the `researchers` table — which holds the Phase 6 AES-256-GCM encrypted sensitive data — is deliberately dropped:

```sql
DROP TABLE researchers;
```

Run as root, directly in phpMyAdmin's SQL tab (with `grantdb` selected), **after** the backup above has been taken.

## 3. Proof the damage is real
- `SHOW TABLES;` no longer lists `researchers`.
- Opening `view_researchers.php` in the app (logged in as `app_dba`) throws a database error, since the table it queries no longer exists.

## 4. Restore procedure

```powershell
& "C:\xampp\mysql\bin\mysql.exe" -u root grantdb < "backup\grantdb_backup_<the exact filename from step 1>.sql"
```

This re-runs every `DROP TABLE IF EXISTS` / `CREATE TABLE` / `INSERT` statement in the backup file, which restores **all** tables to exactly the state they were in at backup time (a full database restore, not a single-table patch — the realistic way `mysqldump` recovery works, and worth stating plainly rather than implying something more surgical happened).

## 5. Verifying integrity of the recovered data
Restoring a table existing again is not enough evidence on its own (the brief is explicit: "showing that a backup file exists will not be sufficient"). Three checks confirm the data itself is intact, not just present:

1. `SELECT COUNT(*) FROM researchers;` → should return 3 (the original row count).
2. Re-run `tools/decrypt_check.php` — if the AES-256-GCM encrypted bytes had been corrupted or truncated by the backup/restore process, decryption would fail loudly (GCM's authentication tag check). A clean decrypt of all 3 rows back to their original fake values proves the binary `VARBINARY` data survived the dump/restore round-trip byte-for-byte.
3. Re-open `view_researchers.php` in the app and confirm it works again, showing the same 3 researchers with the same decrypted values as before the simulated loss.

## 6. Known limitations
- This is a **manual, on-demand** backup, not a scheduled/automated one (e.g. no Windows Task Scheduler job or cron-equivalent) — flagged here rather than built, as out of scope for a single lab VM.
- The restore is a full-database restore, not table-level. A real production recovery might use selective restore for a single accidentally-dropped table without touching unrelated tables; `mysqldump` backups of a whole database don't easily support that without extra tooling, and demonstrating the realistic default behavior was judged more honest than making the recovery look more surgical than it is.
- The backup file itself is **not encrypted at rest** (it's a plain-text `.sql` file containing the same AES-ciphertext bytes as the live database, but also plaintext for everything that isn't an encrypted column, such as proposal titles). A production environment would encrypt backup files and control access to the backup storage location separately — noted as a planned improvement, not implemented in this lab.
- Backups are stored locally only (`backup/` folder on this VM), not copied off-site — single point of failure if the whole VM is lost. Acceptable for a course lab; would not be acceptable for a real production system.

## 7. Evidence checklist
- `P8-01-backup-created.png`: the `mysqldump` command running successfully and the resulting `.sql` file's existence/size (e.g. `dir backup`).
- `P8-02-table-dropped.png`: `SHOW TABLES;` confirming `researchers` is gone, right after the `DROP TABLE`.
- `P8-03-app-broken.png`: `view_researchers.php` throwing an error because the table no longer exists.
- `P8-04-restore-command.png`: the restore command running without errors.
- `P8-05-table-restored.png`: `SHOW TABLES;` showing `researchers` again, plus `SELECT COUNT(*) FROM researchers;` returning 3.
- `P8-06-decrypt-verified.png`: `decrypt_check.php` run again after restore, showing all 3 rows decrypt correctly.
- `P8-07-app-working-again.png`: `view_researchers.php` working again in the browser, same data as before the simulated loss.
