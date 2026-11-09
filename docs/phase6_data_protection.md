# Phase 6: Sensitive Data Protection

## 1. Sensitive data identified
From the Phase 1 classification (`docs/phase1_analysis.md`, section 5), three columns in `researchers` were marked **Restricted**: `national_id_enc`, `phone_enc`, `bank_account_enc`. These were defined as `VARBINARY` from the start, anticipating encryption, but Phase 4's sample data inserted readable fake values directly into them with no actual encryption applied. This phase implements the encryption those columns were designed for.

Passwords (`users.password_hash`) were already protected in Phase 3 with `password_hash()` (bcrypt) — a one-way hash is the correct mechanism there, not encryption, since the application never needs to recover the original password, only verify a guess against it.

## 2. Mechanism chosen: AES-256-GCM, applied in PHP
Encryption is done in the **application layer** (`app/includes/crypto.php`), not with MySQL's built-in `AES_ENCRYPT()`. Reason: `AES_ENCRYPT()` requires passing the key as a literal argument inside the SQL query text itself, which means the key would appear in the general query log, slow query log, and `SHOW PROCESSLIST` — defeating the purpose of a secret key. Doing it in PHP keeps the key out of SQL entirely.

**AES-256-GCM** specifically (not AES-CBC) was chosen because it is an *authenticated* encryption mode: it provides both
- **Confidentiality** — the stored bytes are unreadable without the key, and
- **Integrity** — a 16-byte authentication tag is stored alongside the ciphertext; if the stored bytes are altered in any way (by a bug, corruption, or a malicious direct database edit), decryption fails loudly instead of silently returning corrupted data.

Each encrypted value is stored as `IV (12 bytes) || TAG (16 bytes) || CIPHERTEXT`, and a fresh random IV is generated for every single encryption operation (`random_bytes(12)`), which is required for GCM's security guarantees — reusing an IV with the same key would leak information about the plaintext.

## 3. Data at rest vs data in transit

| Protection | Status |
|---|---|
| **Data at rest** (the database files on disk) |  Implemented this phase: `national_id_enc`, `phone_enc`, `bank_account_enc` are AES-256-GCM encrypted; a stolen `.frm`/`.ibd` file or `mysqldump` backup reveals only ciphertext |
| **Data in transit** (application ↔ database, browser ↔ application) |  Not yet enabled. The Phase 1 baseline evidence (`P9-before-01-server-info.png`) already shows "SSL is not used" for the database connection, and the application still runs on plain HTTP. This is addressed in Phase 9 (hardening): enabling `require_secure_transport` on MariaDB and HTTPS via a certificate for Apache |

This gap is intentional to call out, not hidden: encrypting data at rest does not protect it while it travels unencrypted between the browser, the web server and the database in the meantime.

## 4. Key management principles

| Principle | How it's applied here | Limitation (be honest about this) |
|---|---|---|
| **Secure generation** | `random_bytes(32)` — PHP's CSPRNG, not a password or a predictable value (`tools/generate_key.php`) | None for a lab; in production this would typically come from a dedicated key-management service (e.g. a hardware security module or cloud KMS) rather than a local file |
| **Separation from the data it protects** | The key file (`keys/encryption.key.php`) lives outside the database entirely, and outside both web-servable folders (`app/`, `app_vulnerable/`) — never reachable over HTTP | On this single VM, the same OS account that runs PHP can also read the key file; a true separation of duties would put the key in a separate, access-controlled system |
| **Excluded from version control** | `keys/encryption.key.php` is in `.gitignore`; only a template (`keys/encryption.key.example.php`, no real key) is committed | — |
| **Restricted file permissions** | `generate_key.php` sets the file to `0600` (owner read/write only) where the filesystem supports it | Windows NTFS permissions differ from Unix mode bits; this is a stronger guarantee on the eventual Linux/production deployment than on this Windows lab VM |
| **No key in logs or query text** | Encryption happens entirely in PHP; the key is never passed as a SQL literal | — |
| **Rotation** | Not implemented in this lab | A real rotation strategy would require decrypting all affected rows with the old key and re-encrypting with a new one — a planned improvement, noted here rather than built, given the scope of this course project |

## 5. Verification
- `tools/migrate_encrypt_researchers.php` encrypted all 3 existing researcher rows.
- `tools/decrypt_check.php` confirms every value decrypts back to its original fake plaintext exactly (`P6-01-decrypt-verification.png`).
- A direct SQL query as `root` (`SELECT HEX(national_id_enc) ...`) shows only unreadable ciphertext bytes, confirming the data is genuinely encrypted at rest, not just hidden by the application (`P6-02-raw-encrypted-bytes.png`).

## 6. Why RBAC alone (Phase 2) was not enough
Phase 2 already restricts which *roles* can see these columns (only `FinanceOfficer` can read `bank_account_enc`, for example). But RBAC only controls access **through the database's own privilege system** — it does nothing to protect the data if someone reads the raw files directly (a stolen disk, a leaked `mysqldump` backup, or a `DBA`-level account that can `SELECT *` on everything, as `role_dba` does). Encryption is the layer that still holds even when the access-control layer is bypassed entirely.
