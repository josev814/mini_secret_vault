<?php
namespace Vault;

class Db {
    private static $pdo = null;

    public static function get($host='db', $db='app',$user='user',$pass='pass'): PDO {
        if (self::$pdo) return self::$pdo;
        $host = getenv('DB_HOST') ?: $host;
        $db = getenv('DB_DATABASE') ?: $db;
        $user = getenv('DB_USER') ?: $user;
        $pass = getenv('DB_PASS') ?: $pass;
        $dsn = "mysql:host={$host};dbname={$db};charset=utf8mb4";
        $opt = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];
        self::$pdo = new \PDO($dsn, $user, $pass, $opt);
        return self::$pdo;
    }
}
