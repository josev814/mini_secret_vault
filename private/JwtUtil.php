<?php
class JwtUtil {
    private static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    private static function base64url_decode($data) {
        $remainder = strlen($data) % 4;
        if ($remainder) $data .= str_repeat('=', 4 - $remainder);
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public static function createAccessToken(string $sub, int $ttlSeconds = 900): array {
        $hdr = ['alg' => 'HS256', 'typ' => 'JWT'];
        $now = time();
        $jti = bin2hex(random_bytes(16));
        $payload = [
            'iss' => getenv('APP_ISS') ?: 'mini-vault',
            'aud' => getenv('APP_AUD') ?: 'mini-vault-clients',
            'sub' => $sub,
            'iat' => $now,
            'exp' => $now + $ttlSeconds,
            'jti' => $jti,
        ];
        $sec = getenv('JWT_SECRET') ?: 'dev-secret';
        $header = self::base64url_encode(json_encode($hdr));
        $body = self::base64url_encode(json_encode($payload));
        $sig = hash_hmac('sha256', "$header.$body", $sec, true);
        $token = "$header.$body." . self::base64url_encode($sig);
        return ['token' => $token, 'jti' => $jti, 'exp' => $payload['exp']];
    }

    public static function verifyAccessToken(string $jwt, ?\PDO $pdo = null) {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) return false;
        [$h64, $b64, $s64] = $parts;

        $sec = getenv('JWT_SECRET') ?: 'dev-secret';
        $sig = self::base64url_decode($s64);
        $expected = hash_hmac('sha256', "$h64.$b64", $sec, true);
        if (!hash_equals($expected, $sig)) return false;
        
        $payload = json_decode(self::base64url_decode($b64), true);
        if (!$payload) return false;
        if (($payload['iss'] ?? '') !== (getenv('APP_ISS') ?: 'mini-vault')) return false;
        if (($payload['aud'] ?? '') !== (getenv('APP_AUD') ?: 'mini-vault-clients')) return false;
        if (isset($payload['exp']) && time() > $payload['exp']) return false;
        
        $pdo = $pdo ?: Db::get('apphost','app', 'user', 'pass');
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM revoked_jtis WHERE jti = ?');
        $stmt->execute([$payload['jti']]);
        if ($stmt->fetchColumn() > 0) return false;
        
        return $payload;
    }

    public static function sign(array $payload, int $expMinutes = 60): string {
        $hdr = ['alg' => 'HS256', 'typ' => 'JWT'];
        $now = time();
        $payload['iat'] = $now;
        $payload['exp'] = $now + ($expMinutes * 60);
        $sec = getenv('JWT_SECRET') ?: 'dev-secret';
        $header = self::base64url_encode(json_encode($hdr));
        $body = self::base64url_encode(json_encode($payload));
        $sig = hash_hmac('sha256', "$header.$body", $sec, true);
        return "$header.$body." . self::base64url_encode($sig);
    }

    public static function verify(string $token) {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return false;
        [$headerB64, $bodyB64, $sigB64] = $parts;
        $sec = getenv('JWT_SECRET') ?: 'dev-secret';
        $sig = self::base64url_decode($sigB64);
        $expected = hash_hmac('sha256', "$headerB64.$bodyB64", $sec, true);
        if (!hash_equals($expected, $sig)) return false;
        $payload = json_decode(self::base64url_decode($bodyB64), true);
        if (!$payload) return false;
        if (isset($payload['exp']) && time() > $payload['exp']) return false;
        return $payload;
    }
}
