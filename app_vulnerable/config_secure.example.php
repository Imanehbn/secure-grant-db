<?php
// Copy to config_secure.php (ignored by Git) and set the generated password for app_search.
// NEVER commit config_secure.php.
return [
    'db_host' => 'localhost',
    'db_name' => 'grantdb',
    'db_user' => 'app_search',
    'db_pass' => 'PUT_PASSWORD_HERE',
];
