<?php
$config = require __DIR__ . '/config.php';

$db = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
$q = $_GET['q'] ?? '';
$sql = "SELECT proposal_id, title, status FROM proposals WHERE title LIKE '%" . $q . "%'";
$result = $db->query($sql);

if ($result === false) {
    echo "<p style='color:red'><strong>Database error:</strong> " . $db->error . "</p>";
} else {
    while ($row = $result->fetch_assoc()) {
        echo "<p>#" . $row['proposal_id'] . " — " . $row['title'] . " (" . $row['status'] . ")</p>";
    }
}
?>
<form method="get">
    <input type="text" name="q" value="<?= $q ?>">
    <button type="submit">Search</button>
</form>