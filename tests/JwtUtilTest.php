<?php
use PHPUnit\Framework\TestCase;
use TestMocks\Db as MockDb;

require_once __DIR__ . '/../private/JwtUtil.php';

class JwtUtilTest extends TestCase {
    private $pdo;

    protected function setUp(): void {
        // in-memory SQLite for revocation table
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->exec('CREATE TABLE revoked_jtis (jti TEXT PRIMARY KEY)');
    }

    public function testGenerateAndValidate() {
        $token = JwtUtil::sign(['user_id'=>1], 60);
        $payload = JwtUtil::verify($token);
        $this->assertEquals(1, $payload['user_id']);
    }

    public function testRefresh() {
        $token = JwtUtil::sign(['user_id'=>1], 60);
        $payload = JwtUtil::verify($token);
        $this->assertEquals(1, $payload['user_id']);

        $res = JwtUtil::createAccessToken('user-1');
        $payload = JwtUtil::verifyAccessToken($res['token'], $this->pdo);
        $this->assertEquals('user-1', $payload['sub']);
    }

    public function testRevokedToken() {
        $res = JwtUtil::createAccessToken('user-2');
        $parts = explode('.', $res['token']);
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);

        // insert jti into revoked table
        $stmt = $this->pdo->prepare('INSERT INTO revoked_jtis (jti) VALUES (?)');
        $stmt->execute([$payload['jti']]);

        // token should now fail
        $validated = JwtUtil::verifyAccessToken($res['token'], $this->pdo);
        $this->assertFalse($validated);
    }
}