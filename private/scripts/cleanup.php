<?php
use Vault\Db;
use Vault\CryptoUtil;

$pdo_app = Db::get('apphost','app', 'user', 'pass');

// Expired refresh tokens & revoked JWTs in app DB
$pdo_app->exec('DELETE FROM revoked_jtis WHERE expires_at < NOW()');
$pdo_app->exec('DELETE FROM refresh_tokens WHERE expires_at < NOW()');
$pdo_app->exec('DELETE FROM revoked_tokens WHERE expires_at < NOW()');

// Optionally remove old audit logs from secrets DB
$pdo_secrets = Db::get('secretshost','secrets', 'user', 'pass');
$pdo_secrets->exec('DELETE FROM audit_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 180 DAY)');
