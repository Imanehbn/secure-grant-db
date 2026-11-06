<?php
declare(strict_types=1);

/**
 * Phase 6: application-level encryption for sensitive columns
 * (researchers.national_id_enc, phone_enc, bank_account_enc).
 *
 * AES-256-GCM is used because it provides BOTH confidentiality (the data
 * is unreadable without the key) AND integrity (any tampering with the
 * stored bytes is detected on decryption, via the authentication tag).
 * A plain AES-CBC scheme would only give confidentiality.
 *
 * Each encrypted value is stored as: IV (12 bytes) || TAG (16 bytes) || CIPHERTEXT
 * all concatenated into one binary string, matching the VARBINARY columns
 * already defined in Phase 1's schema.
 */

const CIPHER   = 'aes-256-gcm';
const IV_LEN   = 12; // 96-bit nonce, the recommended size for GCM
const TAG_LEN  = 16; // 128-bit authentication tag

function load_encryption_key(): string
{
    // The key file lives OUTSIDE app/ and app_vulnerable/, so it is never
    // reachable through the web server, and is excluded from Git (.gitignore).
    $keyFile = __DIR__ . '/../../keys/encryption.key.php';
    if (!is_readable($keyFile)) {
        error_log('Encryption key file missing or unreadable: ' . $keyFile);
        throw new RuntimeException('Encryption key unavailable.');
    }
    $key = require $keyFile; // returns a 32-byte binary string
    if (!is_string($key) || strlen($key) !== 32) {
        throw new RuntimeException('Encryption key has the wrong length (expected 32 bytes for AES-256).');
    }
    return $key;
}

function encrypt_value(string $plaintext, ?string $key = null): string
{
    $key = $key ?? load_encryption_key();
    $iv  = random_bytes(IV_LEN); // a fresh random IV for every encryption, never reused
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, '', TAG_LEN);
    if ($ciphertext === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return $iv . $tag . $ciphertext;
}

function decrypt_value(string $blob, ?string $key = null): string
{
    $key = $key ?? load_encryption_key();
    if (strlen($blob) < IV_LEN + TAG_LEN) {
        throw new RuntimeException('Stored value too short to be valid.');
    }
    $iv         = substr($blob, 0, IV_LEN);
    $tag        = substr($blob, IV_LEN, TAG_LEN);
    $ciphertext = substr($blob, IV_LEN + TAG_LEN);
    $plaintext  = openssl_decrypt($ciphertext, CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($plaintext === false) {
        // This fires if the key is wrong OR the data was tampered with -
        // the authentication tag check failed.
        throw new RuntimeException('Decryption failed: wrong key or data was tampered with.');
    }
    return $plaintext;
}
