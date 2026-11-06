<?php
declare(strict_types=1);

/**
 * Phase 6: generates a fresh AES-256 key and writes it to keys/encryption.key.php.
 * Run ONCE from the command line:
 *     & "C:\xampp\php\php.exe" tools\generate_key.php
 *
 * The key is produced with PHP's cryptographically secure random_bytes(),
 * never with a password or a predictable value. It is written as raw
 * binary bytes exported with var_export(), so it can be `require`d directly
 * and used as-is - no decoding step that could be gotten wrong.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}

$keyDir  = __DIR__ . '/../keys';
$keyFile = $keyDir . '/encryption.key.php';

if (!is_dir($keyDir)) {
    mkdir($keyDir, 0700, true);
}

if (file_exists($keyFile)) {
    echo "A key already exists at $keyFile\n";
    echo "Overwriting it would make all currently encrypted data unreadable.\n";
    echo "Type YES to overwrite anyway, or press Ctrl+C to cancel: ";
    $answer = trim((string)fgets(STDIN));
    if ($answer !== 'YES') {
        echo "Cancelled. No changes made.\n";
        exit(0);
    }
}

$key = random_bytes(32); // 256-bit key for AES-256-GCM

$php = "<?php\n// Generated " . date('c') . ". Do NOT commit this file or share its contents.\nreturn " . var_export($key, true) . ";\n";
file_put_contents($keyFile, $php);
chmod($keyFile, 0600); // owner read/write only, where the filesystem supports it

echo "Key written to: $keyFile\n";
echo "This file is in .gitignore and must never be committed.\n";
