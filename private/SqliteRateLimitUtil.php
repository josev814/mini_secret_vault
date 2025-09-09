<?php
namespace Vault;
require_once __DIR__ . '/RateLimitUtil.php';

use PDO;
use Vault\RateLimitUtil;

class SqliteRateLimitUtil extends RateLimitUtil
{
    private PDO $db;
    private string $metaKey = '__last_cleanup';

    public function __construct(
        string $dbPath = null,
        int $defaultLimit = 100,
        int $defaultPeriod = 60,
        int $cleanupInterval = 600
    ) {
        parent::__construct($defaultLimit, $defaultPeriod, $cleanupInterval);
        $dbPath = $dbPath ?? __DIR__ . '/rate_limit.sqlite';
        $this->db = new PDO("sqlite:$dbPath");
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec('PRAGMA journal_mode=WAL');
        $this->cleanupInterval = $cleanupInterval;

        $this->initTable();
    }

    private function initTable(): void
    {
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS rate_limit (
                client_key TEXT PRIMARY KEY,
                count INTEGER NOT NULL,
                start_time INTEGER NOT NULL
            )
        ");

        // Table to track last cleanup timestamp
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS rate_limit_meta (
                meta_key TEXT PRIMARY KEY,
                meta_value INTEGER NOT NULL
            )
        ");

        // Ban table
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS rate_limit_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_key TEXT NOT NULL,
                ban_time INTEGER NOT NULL,
                multiplier INTEGER NOT NULL
            )
        ");

        // Ensure last cleanup exists
        $stmt = $this->db->prepare("INSERT OR IGNORE INTO rate_limit_meta(meta_key, meta_value) VALUES (?, ?)");
        $stmt->execute([$this->metaKey, 0]);
    }

    public function check(string $key, ?int $limit = null, ?int $period = null): void
    {
        $limit = $limit ?? $this->defaultLimit;
        $period = $period ?? $this->defaultPeriod;
        $now = time();

        // Perform cleanup only if interval passed
        if ($this->shouldCleanup($now)) {
            $this->cleanup($period);
            $this->updateLastCleanup($now);
        }

        $stmt = $this->db->prepare("SELECT count, start_time FROM rate_limit WHERE client_key = ?");
        $stmt->execute([$key]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            // first request
            $stmt = $this->db->prepare("
                INSERT INTO rate_limit(client_key, count, start_time)
                VALUES (?, 1, ?)
            ");
            $stmt->execute([$key, $now]);
            return;
        }

        $count = (int)$row['count'];
        $start = (int)$row['start_time'];

        if ($now - $start > $period) {
            // reset window
            $count = 1;
            $start = $now;
        } else {
            $count++;
        }

        // Remaining requests
        $remaining = max(0, $limit - $count);
        $reset = $start + $period;

        // Check for ban multiplier
        $stmt = $this->db->prepare("SELECT MAX(multiplier) as multiplier, MAX(ban_time) as last_ban FROM rate_limit_bans WHERE client_key = ?");
        $stmt->execute([$key]);
        $banRow = $stmt->fetch(PDO::FETCH_ASSOC);
        $multiplier = (int)($banRow['multiplier'] ?? 0);
        $lastBan = (int)($banRow['last_ban'] ?? 0);

        $blocked = false;
        if ($multiplier > 0 && ($lastBan + $period * $multiplier) > $now) {
            $blocked = true;
            $reset = max($reset, $lastBan + $period * $multiplier);
        }

        // Exceeded rate limit
        if ($count > $limit) {
            // Record new ban only if client has made a request since last ban
            $multiplier = $this->recordBan($key);

            $reset = $now + ($period * $multiplier);
            http_response_code(429);
            header('Content-Type: application/json');
            $this->sendRateLimitHeaders($limit, 0, $reset, max(1, $reset - $now), $multiplier, true);

            $date = new \DateTime("@$reset");
            $date->setTimezone(new \DateTimeZone('America/New_York'));
            echo json_encode([
                'error' => 'Rate limit exceeded',
                'retry_after' => $date->format('Y-m-d H:i:s'),
                'multiplier' => $multiplier
            ]);
            exit;
        }

        // Update rate limit table
        $stmt = $this->db->prepare("
            INSERT INTO rate_limit(client_key, count, start_time)
            VALUES (:key, :count, :start)
            ON CONFLICT(client_key) DO UPDATE SET count = :count, start_time = :start
        ");
        $stmt->execute([':key' => $key, ':count' => $count, ':start' => $start]);

        $this->sendRateLimitHeaders($limit, $remaining, $reset, null, $multiplier, $blocked);
    }

    /**
     * Record a ban if client made a request since last ban
     */
    protected function recordBan(string $key): int
    {
        $now = time();

        // Last ban time
        $stmt = $this->db->prepare("SELECT MAX(ban_time) FROM rate_limit_bans WHERE client_key = ?");
        $stmt->execute([$key]);
        $lastBan = (int)$stmt->fetchColumn();

        // Last request time
        $stmt = $this->db->prepare("SELECT start_time FROM rate_limit WHERE client_key = ?");
        $stmt->execute([$key]);
        $lastRequest = (int)$stmt->fetchColumn();

        if ($lastRequest <= $lastBan) {
            // No new ban needed → return current multiplier
            $stmt = $this->db->prepare("SELECT MAX(multiplier) FROM rate_limit_bans WHERE client_key = ?");
            $stmt->execute([$key]);
            return (int)$stmt->fetchColumn() ?: 1;  // fallback to 1 if none exists
        }

        // Count previous bans
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM rate_limit_bans WHERE client_key = ?");
        $stmt->execute([$key]);
        $previousBans = (int)$stmt->fetchColumn();

        $multiplier = $previousBans + 1;

        // Insert new ban record
        $stmt = $this->db->prepare("
            INSERT INTO rate_limit_bans(client_key, ban_time, multiplier)
            VALUES (?, ?, ?)
        ");
        $stmt->execute([$key, $now, $multiplier]);

        return $multiplier;
    }


    /**
     * Get current rate limit status for a client key
     *
     * @param string $key      Client key (IP or token)
     * @param int|null $limit  Max requests per period (defaults to class default)
     * @param int|null $period Time window in seconds (defaults to class default)
     * @param bool $sendHeaders Whether to send X-RateLimit headers
     *
     * @return array ['limit' => int, 'remaining' => int, 'reset' => int]
     */
    public function getRateLimitStatus(string $key, ?int $limit = null, ?int $period = null, bool $sendHeaders = true): array
    {
        $limit  = $limit  ?? $this->defaultLimit;
        $period = $period ?? $this->defaultPeriod;
        $now = time();

        $stmt = $this->db->prepare("SELECT count, start_time FROM rate_limit WHERE client_key = ?");
        $stmt->execute([$key]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        if (!$row) {
            $count = 0;
            $start = $now;
        } else {
            $count = (int)$row['count'];
            $start = (int)$row['start_time'];

            // Reset window if expired
            if ($now - $start > $period) {
                $count = 0;
                $start = $now;
            }
        }

        $remaining = max(0, $limit - $count);
        $reset = $start + $period;

        // Ban info
        $stmt = $this->db->prepare("SELECT MAX(multiplier) as multiplier, MAX(ban_time) as last_ban FROM rate_limit_bans WHERE client_key = ?");
        $stmt->execute([$key]);
        $banRow = $stmt->fetch(PDO::FETCH_ASSOC);

        $multiplier = (int)($banRow['multiplier'] ?? 0);
        $lastBan = (int)($banRow['last_ban'] ?? 0);
        $blocked = false;
        $penaltyExpires = 0;

        if ($multiplier > 0 && ($lastBan + $period * $multiplier) > $now) {
            $blocked = true;
            $penaltyExpires = $lastBan + $period * $multiplier;
            $reset = max($reset, $penaltyExpires);
        }

        if ($sendHeaders) {
            $this->sendRateLimitHeaders($limit, $remaining, $reset, null, $multiplier, $blocked);
        }

        $date = new \DateTime("@$reset");
        $date->setTimezone(new \DateTimeZone('America/New_York'));

        return [
            'limit' => $limit,
            'remaining' => $remaining,
            'reset' => $date->format('Y-m-d H:i:s'),
            'multiplier' => $multiplier,
            'blocked' => $blocked,
            'penalty_expires' => $penaltyExpires ? (new \DateTime("@$penaltyExpires"))->setTimezone(new \DateTimeZone('America/New_York'))->format('Y-m-d H:i:s') : null
        ];
    }


    public function reset(string $key, ?int $limit = null, ?int $period = null): void
    {
        $limit  = $limit  ?? $this->defaultLimit;
        $period = $period ?? $this->defaultPeriod;
        $stmt = $this->db->prepare("DELETE FROM rate_limit WHERE client_key = ?");
        $stmt->execute([$key]);
        $now = time();
        $reset = $now + $period;

        // Full reset → send headers showing full quota restored
        $this->sendRateLimitHeaders($limit, $limit, $reset);
    }

    /**
     * Check if it's time to cleanup
     */
    protected function shouldCleanup(int $now): bool
    {
        $stmt = $this->db->prepare("SELECT meta_value FROM rate_limit_meta WHERE meta_key = ?");
        $stmt->execute([$this->metaKey]);
        $lastCleanup = (int)$stmt->fetchColumn();
        return ($now - $lastCleanup) >= $this->cleanupInterval;
    }

    /**
     * Update last cleanup timestamp
     */
    protected function updateLastCleanup(int $timestamp): void
    {
        $stmt = $this->db->prepare("UPDATE rate_limit_meta SET meta_value = ? WHERE meta_key = ?");
        $stmt->execute([$timestamp, $this->metaKey]);
    }

    /**
     * Clean up expired rate limit entries
     */
    public function cleanup(int $period): void
    {
        $threshold = time() - $period;
        $stmt = $this->db->prepare("DELETE FROM rate_limit WHERE start_time <= ?");
        $stmt->execute([$threshold]);

        // Cleanup bans older than 30 days
        $this->cleanupBans();
    }

    public function cleanupBans($days=1): void
    {
        $threshold = time() - ($days * 24 * 60 * 60);
        $stmt = $this->db->prepare("DELETE FROM rate_limit_bans WHERE ban_time <= ?");
        $stmt->execute([$threshold]);
    }
}
