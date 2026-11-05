# Phase 5: SQL Injection Prevention and Secure Coding

## 1. What changed
The vulnerable component from Phase 4 (`app_vulnerable/search.php`) was rewritten as `app_vulnerable/search_secure.php`, kept side by side with the original so both can be compared directly. Three independent fixes were applied, matching the controls the brief requires.

## 2. The three fixes

### Fix 1: Prepared statement (removes the injection point itself)
**Before (Phase 4):**
```php
$sql = "SELECT proposal_id, title, status FROM proposals WHERE title LIKE '%" . $q . "%'";
$db->query($sql);
```
**After (Phase 5):**
```php
$stmt = $db->prepare("SELECT proposal_id, title, status FROM proposals WHERE title LIKE CONCAT('%', ?, '%')");
$stmt->bind_param('s', $q);
$stmt->execute();
```
The query's structure is sent to the database separately from the user's input, and the input is sent labeled as a string value. The database can no longer be tricked into treating part of the input as SQL syntax, regardless of what characters it contains.

### Fix 2: Least-privileged database account
**Before:** `app_vuln` — `SELECT` on every table in `grantdb`.
**After:** `app_search` — `SELECT` on exactly 3 columns (`proposal_id, title, status`) of one table (`proposals`). See `sql/05_secure_account.sql`.
Even in a scenario where an injection somehow still succeeded, this account has no path to reach the `users` table or any other sensitive data — the account's own permissions are the second line of defense.

### Fix 3: Input validation, secure error handling, output escaping
- Input is rejected if longer than 100 characters or containing anything other than letters, numbers, spaces and hyphens.
- Database errors are logged server-side (`error_log()`) and never shown to the visitor; a generic message is displayed instead.
- All output is passed through `htmlspecialchars()` before being echoed, closing a secondary cross-site-scripting weakness present in the Phase 4 version.

## 3. Verification: before vs after

| Test | Phase 4 (vulnerable) result | Phase 5 (fixed) result |
|---|---|---|
| Normal search (`q=Water`) | 1 correct result | Same, 1 correct result (`P5-01`) |
| Always-true bypass (`q=%' OR '1'='1`) | All 7 proposals returned, including 2 confidential drafts, via a manipulated WHERE clause (`P4-02`) | Payload rejected by validation; result is identical to an ordinary blank search (`P5-02`, compared against `P5-02-blank-search-baseline`) — the payload has no special effect, unlike in Phase 4 |
| UNION data exfiltration (`q=...UNION SELECT user_id, username, password_hash FROM users -- -`) | Usernames and password hashes of all 8 accounts displayed (`P4-03`) | No data from `users` appears; only the same 7 ordinary proposal rows (`P5-03`) |

## 4. Why the fix is sufficient
Each of the three controls independently prevents the demonstrated attacks:
- The prepared statement means a crafted payload is never parsed as SQL, even without validation.
- The input validation adds a second, independent layer that rejects the payload's characters outright.
- The least-privileged account ensures that even a hypothetical bypass of both of the above could never reach the `users` table, since `app_search` has no privilege on it at all.

This matches the defense-in-depth pattern already used for the production login system in Phase 3 (`app_login`), where each layer (hashing, prepared statements, scoped privileges, lockout) also stands on its own.

## 5. Known limitation carried over
The search feature itself does not filter by proposal status (it only filters by title), so an ordinary blank search already returns all proposals including drafts, in both the vulnerable and fixed versions. This is a pre-existing feature gap unrelated to the SQL injection fix — noted here for completeness, and a reasonable future improvement would be adding a `WHERE status = 'Approved'` condition for any unauthenticated visitor.
