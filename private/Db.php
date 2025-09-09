<?php
namespace Vault;

class Db {
    private static array $connections = [];
    private static int  $maxAttempts = 10;
    private static int $baseDelay = 1;

    public static function get(string $host, string $db, string $user, string $pass): \PDO {
        $dsn = "mysql:host={$host};dbname={$db};charset=utf8mb4";
        if(!isset(self::$connections[$dsn])){
            $opt = [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                \PDO::ATTR_EMULATE_PREPARES => false,
            ];
            $attempt = 0;
            while ($attempt < self::$maxAttempts) {
                try {
                    self::$connections[$dsn] = new \PDO($dsn, $user, $pass, $opt);
                    break; // Success, exit loop
                } catch (\PDOException $e) {
                    $attempt++;
                    if ($attempt >= self::$maxAttempts) {
                        error_log("Database connection failed after {$attempt} attempts: " . $e->getCode());
                        throw new \RuntimeException("Database connection failed. Try again later.");
                    }

                    // Jittered delay: baseDelay ± 50%
                    $min = max(1, (int)(self::$baseDelay * 0.5));
                    $max = (int)(self::$baseDelay * 1.5);
                    $jitter = rand($min, $max);

                    sleep($jitter);
                }
            }
        }
        return self::$connections[$dsn];
    }
}
