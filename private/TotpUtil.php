<?php
namespace Vault;

use Endroid\QrCode\QrCode;
use Endroid\QrCode\Writer\PngWriter;

class TotpUtil {
    private const TIME_STEP = 30; // seconds
    private const DIGITS = 6;
    private const ALGORITHM = 'sha512';

    /**
     * Generate a secret key for TOTP (base32 encoded)
     * @return string Base32-encoded secret
     */
    public static function generateSecret(): string {
        $bytes = random_bytes(20);
        return self::base32Encode($bytes);
    }

    /**
     * Generate a provisioning URI for QR code generation
     * Compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.
     * @param string $secret The TOTP secret
     * @param string $username The username for this account
     * @param string $issuer The issuer name (appears in authenticator app)
     * @return string The provisioning URI (otpauth://)
     */
    public static function getProvisioningUri(string $secret, string $username, string $issuer = 'Mini-Vault'): string {
        $label = urlencode($issuer) . ':' . urlencode($username);
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => self::ALGORITHM,
            'digits' => self::DIGITS,
            'period' => self::TIME_STEP,
        ]);
        return "otpauth://totp/$label?$params";
    }

    /**
     * Generate a QR code image (PNG) as base64-encoded data URI
     * @param string $provisioning_uri The provisioning URI from getProvisioningUri()
     * @return string Base64-encoded data URI (data:image/png;base64,...)
     */
    public static function generateQrCode(string $provisioning_uri): string {
        $qrCode = new QrCode($provisioning_uri);
        $writer = new PngWriter();
        $result = $writer->write($qrCode);
        return 'data:image/png;base64,' . base64_encode($result->getString());
    }

    /**
     * Get the secret without base32 padding (for manual entry into authenticator apps)
     * @param string $secret The base32-encoded secret with padding
     * @return string Secret without padding
     */
    public static function getSecretWithoutPadding(string $secret): string {
        return rtrim($secret, '=');
    }

    /**
     * Verify a TOTP code (allows for time drift of ±1 window)
     * @param string $secret The TOTP secret
     * @param string $code The 6-digit code to verify
     * @param int $timeWindow Number of 30-second windows to check (default 1 allows ±1 drift)
     * @return bool True if code is valid
     */
    public static function verify(string $secret, string $code, int $timeWindow = 1): bool {
        $code = str_pad($code, self::DIGITS, '0', STR_PAD_LEFT);
        $decodedSecret = self::base32Decode($secret);

        if ($decodedSecret === false) {
            return false;
        }

        $now = time();
        $timeCounter = intdiv($now, self::TIME_STEP);

        // Check current time window and ±$timeWindow for drift tolerance
        for ($i = -$timeWindow; $i <= $timeWindow; $i++) {
            $counter = $timeCounter + $i;
            $hash = hash_hmac(
                self::ALGORITHM,
                pack('N', 0) . pack('N', $counter),
                $decodedSecret,
                true
            );

            $offset = ord($hash[-1]) & 0x0F;
            $otp = (unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF) % (10 ** self::DIGITS);
            $otpStr = str_pad((string)$otp, self::DIGITS, '0', STR_PAD_LEFT);

            if (hash_equals($otpStr, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Base32 encode (RFC 4648)
     * @param string $data Raw data to encode
     * @return string Base32-encoded string
     */
    private static function base32Encode(string $data): string {
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $encoded = '';
        $bits = 0;
        $value = 0;

        for ($i = 0; $i < strlen($data); $i++) {
            $value = ($value << 8) | ord($data[$i]);
            $bits += 8;

            while ($bits >= 5) {
                $bits -= 5;
                $encoded .= $base32Chars[($value >> $bits) & 0x1F];
            }
        }

        if ($bits > 0) {
            $encoded .= $base32Chars[($value << (5 - $bits)) & 0x1F];
        }

        // Add padding
        while (strlen($encoded) % 8 !== 0) {
            $encoded .= '=';
        }

        return $encoded;
    }

    /**
     * Base32 decode (RFC 4648)
     * @param string $data Base32-encoded string to decode
     * @return string|false Raw decoded data, or false on invalid input
     */
    private static function base32Decode(string $data): string|false {
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = strtoupper($data);
        $decoded = '';
        $bits = 0;
        $value = 0;

        for ($i = 0; $i < strlen($data); $i++) {
            $char = $data[$i];
            if ($char === '=') {
                break;
            }

            $charPos = strpos($base32Chars, $char);
            if ($charPos === false) {
                return false;
            }

            $value = ($value << 5) | $charPos;
            $bits += 5;

            if ($bits >= 8) {
                $bits -= 8;
                $decoded .= chr(($value >> $bits) & 0xFF);
            }
        }

        return $decoded;
    }
}
