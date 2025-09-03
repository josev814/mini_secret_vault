<?php
// tests/bootstrap_coverage.php
declare(strict_types=1);

require_once __DIR__ . '/mocks/Db.php';

if (!class_exists('Db')) {
    class_alias(\TestMocks\Db::class, 'Db');
}

// Optional: define environment variables for JWT, KEKs, etc.
putenv('JWT_SECRET=dev-secret');
putenv('REFRESH_TOKEN_SECRET=dev-refresh-secret');
putenv('MASTER_KEK_B64=' . base64_encode(random_bytes(32)));
putenv('MASTER_KEKS_JSON=' . json_encode([['id'=>'primary','b64'=>base64_encode(random_bytes(32))]]));
putenv('MASTER_KEK_PRIMARY_ID=primary');
putenv('APP_ISS=mini-vault');
putenv('APP_AUD=mini-vault-clients');

// Composer autoload
require __DIR__ . '/../vendor/autoload.php';

// Then load utils AFTER the mock is ready
// require_once __DIR__ . '/../private/JwtUtil.php';
// require_once __DIR__ . '/../private/RefreshTokenUtil.php';
