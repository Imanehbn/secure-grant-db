-- =====================================================================
-- GrantDB - Phase 5: least-privileged account for the FIXED search page
--
-- Replaces app_vuln. This account can see ONLY the 3 columns the search
-- page actually needs, on ONE table. It cannot read users, researchers,
-- grants, or anything else - so even if a future bug slipped through,
-- the blast radius is tiny compared to app_vuln's SELECT on grantdb.*.
--
-- The password placeholder is replaced by a generated one at run time,
-- same pattern as Phase 2 and Phase 4. Never commit a real password.
-- =====================================================================

CREATE OR REPLACE USER 'app_search'@'localhost' IDENTIFIED BY 'CHANGE_ME_search';
GRANT SELECT (proposal_id, title, status) ON grantdb.proposals TO 'app_search'@'localhost';
FLUSH PRIVILEGES;
