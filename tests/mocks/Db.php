<?php
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