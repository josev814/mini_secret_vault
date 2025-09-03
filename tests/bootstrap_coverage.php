<?php
// tests/bootstrap_coverage.php
declare(strict_types=1);

namespace TestMocks;

/**
 * Override the Db class so that all PDO calls return mocks
 * during PHPUnit coverage runs. This prevents network errors.
 */

class Db {
    public static function get($host, $db, $user, $pass) {
        return new class {
            public function prepare($query) {
                return new class {
                    public function execute($args = []) {
                        // No-op
                        return true;
                    }

                    public function fetch($fetch_style = null) {
                        return false;
                    }

                    public function fetchColumn($col = 0) {
                        return 0;
                    }

                    public function lastInsertId($name = null) {
                        return 1;
                    }
                };
            }

            public function exec($sql) {
                return 1;
            }
        };
    }
}

// Optional: define environment variables for JWT, KEKs, etc.
putenv('JWT_SECRET=dev-secret');
putenv('REFRESH_TOKEN_SECRET=dev-refresh-secret');
putenv('MASTER_KEK_B64=' . base64_encode(random_bytes(32)));
putenv('MASTER_KEKS_JSON=' . json_encode([['id'=>'primary','b64'=>base64_encode(random_bytes(32))]]));
putenv('MASTER_KEK_PRIMARY_ID=primary');
putenv('APP_ISS=mini-vault');
putenv('APP_AUD=mini-vault-clients');

// Autoload Composer classes
require __DIR__ . '/../vendor/autoload.php';
