<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../JwtUtil.php';

class JwtUtilTest extends TestCase {
    public function testGenerateAndValidate() {
        putenv('JWT_SECRET=supersecret');
        JwtUtil::init();
        $token = JwtUtil::generate(['user_id'=>1], 60);
        $payload = JwtUtil::validate($token);
        $this->assertEquals(1, $payload['user_id']);
    }
}