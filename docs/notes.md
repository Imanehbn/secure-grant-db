# Evidence Notes: Before Hardening (16 Oct 2026)

**Environment:** Windows 11 VM (VMware), XAMPP, MariaDB 10.4.32, PHP 8.2.12,
Apache 2.4.58, phpMyAdmin.

## Capture 1: Server information (P9-before-01-server-info.png)
- **Observation:** The page states "SSL is not used". The session is connected
  as root@localhost over TCP/IP.
- **What it proves:** The connection between the client and the database is not
  encrypted, and the administrator account is the one being used.
- **Risk:** Data and credentials sent to the database could be read by anyone
  who can capture the traffic (data in transit). Using root exposes full
  administrative power.
- **Planned fix:** Enable TLS for database connections; use a dedicated
  least-privileged account for the application.

## Capture 2: Database accounts (P9-before-02-users.png)
- **Observation:** 5 accounts exist: root@localhost, root@127.0.0.1, root@::1,
  pma@localhost and labuser@localhost. The first four show an empty password
  column; only labuser has a password hash.
- **What it proves:** Anyone who can reach the server locally can log in as the
  database administrator without a password. Three separate root accounts
  triple the exposure. The pma account also has no password.
- **Risk:** Full compromise of every database with no authentication effort.
- **Planned fix:** Set a strong root password, remove redundant root accounts,
  set a password for or remove pma, and review the purpose of labuser.
- **Note:** The labuser hash is partly visible. Blur it before sharing.

## Capture 3: Databases present (P9-before-03-databases.png)
- **Observation:** information_schema, mysql, performance_schema, phpmyadmin,
  test, university_security.
- **What it proves:** The default `test` database is present. It is an
  unnecessary default component and part of the attack surface.
  university_security is not part of this project.
- **Planned fix:** Drop `test`. Confirm whether university_security is needed;
  if it belongs to another exercise, leave it untouched.

## Capture 4: Privileges of root (P9-before-04-root-grants.png)
- **Observation:** root has GRANT ALL PRIVILEGES on *.* and a GRANT PROXY
  privilege.
- **What it proves:** Root has unrestricted control over every database and can
  grant privileges to others. This is the opposite of least privilege.
- **Risk:** If the application ran as root, a single SQL injection would give
  an attacker full control of the server.
- **Planned fix:** Create separate roles and accounts (Phase 2) and never let
  the application connect as root.

## Capture 5: Open database port (P9-before-05-port.png)
## Capture 5: Open database port (P9-before-05-port.png)
- **Observation:** `netstat -an | findstr 3306` shows TCP 0.0.0.0:3306 and
  [::]:3306 in the LISTENING state.
- **What it proves:** The database server accepts connections on every network
  interface (IPv4 and IPv6), not only on the local loopback address. Combined
  with root accounts that have no password (Capture 2), any machine that can
  reach this host on port 3306 could attempt to log in as administrator.
- **Risk:** Unnecessary network exposure of the database; remote brute-force
  and unauthorized access attempts.
- **Planned fix:** Set `bind-address=127.0.0.1` in my.ini so MariaDB only
  accepts local connections, restrict the port with the Windows firewall,
  and re-run netstat to show 127.0.0.1:3306 only.

## Capture 6: Configuration file (P9-before-06-my.ini)
- **Observation:** Copy of the default my.ini taken before any change.
- **What it proves:** This is the baseline configuration. It will be compared
  with the hardened version in Phase 9 (bind-address, logging, and other settings).
  ## Phase 1: Schema import
- The script created grantdb with 11 tables and seeded 6 roles. The 15
  statements executed without failure. This is the baseline for Phase 2