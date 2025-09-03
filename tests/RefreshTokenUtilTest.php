<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../RefreshTokenUtil.php';

class RefreshTokenUtilTest extends TestCase {
    private $pdo;

    protected function setUp(): void {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->exec('CREATE TABLE refresh_tokens (id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT, expires_at TEXT)');
    }

    public function testCreateAndValidate() {
        $user_id = 1;
        $token = RefreshTokenUtil::create($this->pdo, $user_id, 3600);
        $validated_id = RefreshTokenUtil::validate($this->pdo, $token);
        $this->assertEquals($user_id, $validated_id);
    }
}