<?php
use PHPUnit\Framework\TestCase;
use Vault\RefreshTokenUtil;

class RefreshTokenUtilTest extends TestCase {
    private $pdo;

    protected function setUp(): void {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->exec(
            'CREATE TABLE refresh_tokens (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                token_hash TEXT,
                expires_at TEXT,
                revoked_at TEXT
            )'
        );
    }

    public function testCreateAndValidate() {
        $user_id = 1;
        $tokenData = RefreshTokenUtil::issueRefreshToken($this->pdo, $user_id, 3600);
        $this->assertArrayHasKey('token', $tokenData);
        $validated_id = RefreshTokenUtil::findTokenRow($this->pdo, $tokenData['token']);
        $this->assertEquals($user_id, $validated_id['user_id']);
    }

    public function testExpiredToken() {
        $user_id = 2;
        $resp = RefreshTokenUtil::issueRefreshToken($this->pdo, $user_id, -10); // already expired
        $this->assertArrayHasKey('token', $resp);
        $token = $resp['token'];
        $validated = RefreshTokenUtil::validate($this->pdo, $token);
        $this->assertFalse($validated);
    }
}