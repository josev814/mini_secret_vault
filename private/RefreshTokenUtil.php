<?php
require_once 'Db.php';

class RefreshTokenUtil {
    public static function issueRefreshToken(int $userId, int $days = 30) {
        $tokenRaw = base64_encode(random_bytes(48));
        $secret = getenv('REFRESH_TOKEN_SECRET') ?: (getenv('JWT_SECRET') ?: 'refresh-secret');
        $hash = hash_hmac('sha256', $tokenRaw, $secret);
        $expiresAt = date('Y-m-d H:i:s', time() + $days * 86400);
        $pdo = Db::get('apphost','app', 'user', 'pass');
        $stmt = $pdo->prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)');
        $stmt->execute([$userId, $hash, $expiresAt]);
        $id = $pdo->lastInsertId();
        return ['token' => $tokenRaw, 'id' => $id, 'expires_at' => $expiresAt];
    }

    public static function findTokenRow(string $tokenRaw) {
        $secret = getenv('REFRESH_TOKEN_SECRET') ?: (getenv('JWT_SECRET') ?: 'refresh-secret');
        $hash = hash_hmac('sha256', $tokenRaw, $secret);
        $pdo = Db::get('apphost','app', 'user', 'pass');
        $stmt = $pdo->prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? LIMIT 1');
        $stmt->execute([$hash]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    public static function revokeRow($id) {
        $pdo = Db::get('apphost','app', 'user', 'pass');
        $stmt = $pdo->prepare('UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = ?');
        $stmt->execute([$id]);
    }
}