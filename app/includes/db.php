<?php
declare(strict_types=1);

// Connects with the least-privileged service account (app_login), never root.
function db_connect(array $config): mysqli
{
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    try {
        $db = new mysqli(
            $config['db_host'],
            $config['app_login_user'],
            $config['app_login_pass'],
            $config['db_name']
        );
        $db->set_charset('utf8mb4');
        return $db;
    } catch (mysqli_sql_exception $e) {
        // Details go to the server log only, never to the visitor.
        error_log('DB connection failed: ' . $e->getMessage());
        http_response_code(500);
        exit('Service temporarily unavailable.');
    }
}
