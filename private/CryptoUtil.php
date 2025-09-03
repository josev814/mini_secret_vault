<?php
// CryptoUtil.php - supports multiple KEKs

namespace Vault; 

class CryptoUtil {
    // parse MASTER_KEKS_JSON or fallback to single MASTER_KEK_B64
    private static function load_master_keks(): array {
        $json = getenv('MASTER_KEKS_JSON') ?: '';
        $arr = [];
        if ($json) {
            $decoded = json_decode($json, true);
            if (!is_array($decoded)) throw new \Exception('MASTER_KEKS_JSON must be valid JSON array');
            foreach ($decoded as $entry) {
                if (!isset($entry['id']) || !isset($entry['b64'])) throw new \Exception('each KEK entry requires id and b64');
                $raw = base64_decode($entry['b64'], true);
                if ($raw === false || strlen($raw) !== 32) throw new \Exception('each KEK b64 must decode to 32 bytes');
                $arr[$entry['id']] = $raw;
            }
            return $arr;
        }

        // fallback single KEK env var for backwards compatibility
        $b64 = getenv('MASTER_KEK_B64') ?: '';
        if (!$b64) throw new \Exception('MASTER KEK not configured');
        $raw = base64_decode($b64, true);
        if ($raw === false || strlen($raw) !== 32) throw new \Exception('MASTER_KEK_B64 must decode to 32 bytes');
        return ['primary' => $raw];
    }

    // derive a KEK from a master key using HKDF (returns raw bytes)
    private static function derive_kek_from_master(string $masterRaw, string $info = 'wrap:v1') : string {
        return hash_hkdf('sha256', $masterRaw, 32, $info, '');
    }

    // get array map id => derived_kek_bytes
    private static function get_derived_keks(): array {
        static $cache = null;
        if ($cache !== null) return $cache;
        $masters = self::load_master_keks();
        $cache = [];
        foreach ($masters as $id => $raw) {
            $cache[$id] = self::derive_kek_from_master($raw, 'wrap:v1');
        }
        return $cache;
    }

    // return [nonce, wrapped_with_tag, kek_id] - uses primary KEK for new wraps
    public static function wrap_dek(string $dek): array {
        $derived = self::get_derived_keks();
        // choose primary: look for first entry labelled 'primary' in JSON ordering (we assume JSON order preserved)
        // PHP preserves insertion order for associative arrays produced from json_decode
        $primary_id = getenv('MASTER_KEK_PRIMARY_ID') ?: array_key_first($derived);
        $kek = $derived[$primary_id];
        $nonce = random_bytes(12);
        $tag = '';
        $wrapped = openssl_encrypt($dek, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $nonce, $tag);
        if ($wrapped === false) throw new \Exception('wrap_dek failed');
        return [$nonce, $wrapped . $tag, $primary_id];
    }

    // Unwrap: use kek_id if provided; otherwise try all known KEKs (useful for older rows)
    public static function unwrap_dek(?string $kek_id, string $nonce, string $wrapped_with_tag): string {
        $derived = self::get_derived_keks();
        $tag = substr($wrapped_with_tag, -16);
        $wrapped = substr($wrapped_with_tag, 0, -16);

        if ($kek_id) {
            if (!isset($derived[$kek_id])) {
                throw new \Exception('KEK id not available: ' . $kek_id);
            }
            $dek = openssl_decrypt($wrapped, 'aes-256-gcm', $derived[$kek_id], OPENSSL_RAW_DATA, $nonce, $tag);
            if ($dek === false) throw new \Exception('unwrap_dek failed with indicated kek_id');
            return $dek;
        }

        // fallback: try all (order: derived array)
        foreach ($derived as $id => $kek) {
            $dek = @openssl_decrypt($wrapped, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $nonce, $tag);
            if ($dek !== false) return $dek;
        }
        throw new \Exception('unwrap_dek failed with all known KEKs');
    }

    // encrypt_secret returns [dek_nonce, dek_wrapped, nonce, tag, ciphertext, kek_id]
    public static function encrypt_secret(string $plaintext, string $aad = ''): array {
        $dek = random_bytes(32);
        [$dek_nonce, $dek_wrapped, $kek_id] = self::wrap_dek($dek);
        $nonce = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $dek, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($cipher === false) throw new \Exception('encrypt_secret failed');
        return [$dek_nonce, $dek_wrapped, $nonce, $tag, $cipher, $kek_id];
    }

    // decrypt_secret requires $kek_id (nullable)
    public static function decrypt_secret(?string $kek_id, string $dek_nonce, string $dek_wrapped, string $nonce, string $tag, string $ciphertext, string $aad = ''): string {
        $dek = self::unwrap_dek($kek_id, $dek_nonce, $dek_wrapped);
        $pt = openssl_decrypt($ciphertext, 'aes-256-gcm', $dek, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($pt === false) throw new \Exception('decrypt_secret failed');
        return $pt;
    }
}
