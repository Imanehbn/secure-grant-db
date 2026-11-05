<?php
$config = require __DIR__ . '/config_secure.php';

$db = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
mysqli_report(MYSQLI_REPORT_OFF);
$q = $_GET['q'] ?? '';
$valid = strlen($q) <= 100 && preg_match('/^[\p{L}\p{N}\s\-]*$/u', $q) === 1;
if (!$valid) {
    $q = '';
}
$stmt = $db->prepare("SELECT proposal_id, title, status FROM proposals WHERE title LIKE CONCAT('%', ?, '%')");
$stmt->bind_param('s', $q);
$stmt->execute();
$result = $stmt->get_result();
function h($s) {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

if ($result === false) {
    error_log('Search query failed: ' . $db->error);
    echo "<p style='color:red'>Something went wrong. Please try again.</p>";
} else {
    while ($row = $result->fetch_assoc()) {
        echo "<p>#" . h($row['proposal_id']) . " — " . h($row['title']) . " (" . h($row['status']) . ")</p>";
    }
}
?>
<form method="get">
    <input type="text" name="q" value="<?= h($q) ?>" maxlength="100">
    <button type="submit">Search</button>
</form>