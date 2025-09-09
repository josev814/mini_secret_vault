<?php
namespace Vault;

abstract class RateLimitUtil
{
    protected int $defaultLimit;
    protected int $defaultPeriod;
    protected int $cleanupInterval;

    public function __construct(int $defaultLimit = 100, int $defaultPeriod = 60, int $cleanupInterval = 600)
    {
        $this->defaultLimit = $defaultLimit;
        $this->defaultPeriod = $defaultPeriod;
        $this->cleanupInterval = $cleanupInterval;
    }

    /**
     * Check the rate limit for a given key
     *
     * @param string $key Unique key per client (IP or token)
     * @param int $limit Max requests per period
     * @param int $period Time window in seconds
     */
    abstract public function check(string $key, ?int $limit = null, ?int $period = null): void;

    /**
     * Send headers with optional multiplier and blocked
     */
    protected function sendRateLimitHeaders(int $limit, int $remaining, int $reset, ?int $retryAfter = null, int $multiplier = 0, bool $blocked = false): void
    {
        header("X-RateLimit-Limit: $limit");
        header("X-RateLimit-Remaining: $remaining");
        header("X-RateLimit-Reset: $reset");

        if ($retryAfter !== null) {
            header("Retry-After: $retryAfter");
        }

        header("X-RateLimit-Multiplier: $multiplier");
        header("X-RateLimit-Blocked: " . ($blocked ? 'true' : 'false'));
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
    abstract public function getRateLimitStatus(string $key, ?int $limit = null, ?int $period = null, bool $sendHeaders = true): array;

    /**
     * Optional: reset the counter for a key
     */
    abstract public function reset(string $key, int $limit = null, ?int $period = null): void;

    /**
     * Check if it's time to cleanup
     */
    abstract protected function shouldCleanup(int $now): bool;

    /**
     * Update last cleanup timestamp
     */
    abstract protected function updateLastCleanup(int $timestamp): void;

    /**
     * Clean up expired rate limit entries
     */
    abstract public function cleanup(int $period): void;
}
