<?php
require_once __DIR__ . '/../private/Db.php';
require_once __DIR__ . '/../private/CryptoUtil.php';
require_once __DIR__ . '/../private/JwtUtil.php';
require_once __DIR__ . '/../private/UserUtil.php';
require_once __DIR__ . '/../private/SqliteRateLimitUtil.php';
use Vault\SqliteRateLimitUtil;
use Vault\Db;
use Vault\CryptoUtil;
use Vault\JwtUtil;
use Vault\UserUtil;

define('API_LIMIT_REQUESTS', 100);
define('API_LIMIT_SECONDS', 60);

// helper: get Authorization bearer
function get_bearer_token() {
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['Authorization'] ?? null;
    $hdr = $hdr ?? apache_request_headers()['Authorization'] ?? null;
    if (!$hdr) return null;
    if (preg_match('/Bearer\s+(\S+)/', $hdr, $m)) return $m[1];
    return null;
}

function require_auth() {
    $token = get_bearer_token();
    if (!$token) api_response(401,['error' => 'missing token']);
    $payload = JwtUtil::verify($token);
    if (!$payload) api_response(401, ['error' => 'invalid token']);
    return $payload;
}

function get_pdo_conn($db='secrets'){
    if($db === 'secrets'){
        //pdo_secrets
        $db_info = [getenv('SECRETS_DB_HOST'),getenv('SECRETS_DB'), getenv('SECRETS_DB_USER'), getenv('SECRETS_DB_PASS')];
    } else {
        //pdo_app
        $db_info = [getenv('APP_DB_HOST'),getenv('APP_DB'), getenv('APP_DB_USER'), getenv('APP_DB_PASS')];
    }
    return Db::get(...$db_info);
}

function api_response($status_code=200, $resp_data=[]){
    http_response_code($status_code);
    echo json_encode($resp_data);
    exit();
}

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// do this before db hit
$rateLimiter = new SqliteRateLimitUtil();
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$token = get_bearer_token();
$clientKey = $token ? "rate:token:$token" : "rate:ip:$ip";
// Configurable limits (or fall back to class defaults)
$limit  = $API_LIMIT_REQUESTS ?? null;  // e.g. 100
$period = $API_LIMIT_SECONDS ?? null;   // e.g. 60
$rateLimiter->check($clientKey, $limit, $period);


// POST Endpoints
if ($method === 'POST') {
    // LOGIN endpoint (existing)
    if ($path === '/login') {
        $data = json_decode(file_get_contents('php://input'), true);
        if (!array_key_exists('username', $data) || !array_key_exists('password', $data)) api_response(404, ['error' => 'Missing required params']);
        $username = $data['username'] ?? '';
        $password = $data['password'] ?? '';
        if (!$username || !$password) {
            api_response(401, ['error' => 'Invalid credentials']);
        }
        $pdo_app = get_pdo_conn('app');

        $userutil = new UserUtil();
        if (! $userutil->validate_user($username, $password, $pdo_app)){
            api_response(401, ['error' => 'Invalid credentials']);
        }

        $token = JwtUtil::sign(['sub' => $username], 120); // 120 min expiry
        api_response(200, ['token' => $token]);
    }
    
    // POST /secret -> create new version
    if ($path === '/secret') {
        $actor = require_auth();
        $data = json_decode(file_get_contents('php://input'), true);
        $name = $data['name'] ?? null;
        $secret = $data['secret'] ?? null;
        if (!$name || !$secret) {
            api_response(400, ['error' => 'name and secret required']);
        }
        
        $pdo_secrets = get_pdo_conn();

        // get max version
        $stmt = $pdo_secrets->prepare('SELECT MAX(version) as v FROM secrets WHERE name = ?');
        $stmt->execute([$name]);
        $vrow = $stmt->fetch();
        $next = ($vrow && $vrow['v']) ? ($vrow['v'] + 1) : 1;

        // encrypt
        $aad = "$name:$next";
        [$dek_nonce, $dek_wrapped, $nonce, $tag, $ciphertext, $kek_id] = CryptoUtil::encrypt_secret($secret, $aad);

        $ins = $pdo_secrets->prepare('INSERT INTO secrets (name, version, ciphertext, nonce, tag, wrapped_dek, kek_id) VALUES (?, ?, ?, ?, ?, ?)');
        $ins->execute([$name, $next, $ciphertext, $nonce, $tag, $dek_wrapped, $kek_id]);

        // audit
        $sid = $pdo_secrets->lastInsertId();
        $a = $pdo_secrets->prepare('INSERT INTO audit_logs (secret_id, action, actor, details) VALUES (?, ?, ?, ?)');
        $a->execute([$sid, 'WRITE', $actor['sub'], json_encode(['version' => $next])]);

        api_response(200,['status' => 'ok', 'name' => $name, 'version' => $next]);
    }
}

if ($method === 'PATCH'){
    // CHANGE PASSWORD endpoint
    if ($path === '/change-password') {
        $actor = require_auth();

        $data = json_decode(file_get_contents('php://input'), true);
        $currentPassword = $data['current_password'] ?? '';
        $newPassword = $data['new_password'] ?? '';

        if (!$currentPassword || !$newPassword) {
            api_response(400, ['error' => 'Current and new passwords are required']);
        }

        $username = $actor['sub'];

        $pdo_app = get_pdo_conn('app');
        $stmt = $pdo_app->prepare('SELECT password_hash FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($currentPassword, $user['password_hash'])) {
            api_response(401, ['error' => 'Invalid credentials']);
        }

        // Hash new password
        $userutil = new UserUtil();
        $newHash = $userutil->encrypt_password($newPassword);

        // Update in database
        $stmt = $pdo_app->prepare('UPDATE users SET password_hash = ? WHERE username = ?');
        $stmt->execute([$newHash, $username]);

        api_response(200, ['message' => 'Password changed successfully']);
    }
}

// GET Endpoints
if ($method === 'GET'){
    // Serve Swagger UI (protected)
    if($path === '/docs') {
        require_auth();
        header('Content-Type: text/html');
        readfile('docs.html');
        exit;
    }

    // Serve dynamic swagger.json (protected)
    if ($path === '/docs/swagger.json') {
        require_auth();
        header('Content-Type: application/json');
        $base = require 'swagger_template.php';
        echo json_encode($base, JSON_PRETTY_PRINT);
        exit;
    }

    // returns the current rate limit status for a token/ip
    if ($path === '/rate-limit-status'){
        $status = $rateLimiter->getRateLimitStatus($clientKey);
        api_response(200, ['rate_limit' => $status]);
    }

    // GET /secret/{name} -> latest
    if (preg_match('#^/secret/([^/]+)$#', $path, $m)) {
        $actor = require_auth();
        $name = $m[1];
        $pdo_secrets = get_pdo_conn();
        $stmt = $pdo_secrets->prepare('SELECT * FROM secrets WHERE name = ? ORDER BY version DESC LIMIT 1');
        $stmt->execute([$name]);
        $row = $stmt->fetch();
        if (!$row) {
            api_response(404, ['error' => 'not found']);
        }
        $aad = "$name:" . $row['version'];
        $pt = CryptoUtil::decrypt_secret(
            $row['kek_id'],
            $row['dek_nonce'],
            $row['wrapped_dek'],
            $row['nonce'],
            $row['tag'],
            $row['ciphertext'],
            $aad
        );
        // audit
        $a = $pdo_secrets->prepare('INSERT INTO audit_logs (secret_id, action, actor, details) VALUES (?, ?, ?, ?)');
        $a->execute([$row['id'], 'READ', $actor['sub'], json_encode(['version' => $row['version']])]);
        api_response(200, ['name' => $name, 'version' => $row['version'], 'secret' => $pt]);
    }

    // GET /secret/{name}/{version}
    if (preg_match('#^/secret/([^/]+)/([0-9]+)$#', $path, $m)) {
        $actor = require_auth();
        $name = $m[1];
        $version = (int)$m[2];
        $pdo_secrets = get_pdo_conn();
        $stmt = $pdo_secrets->prepare('SELECT * FROM secrets WHERE name = ? AND version = ? LIMIT 1');
        $stmt->execute([$name, $version]);
        $row = $stmt->fetch();
        if (!$row) {
            api_response(404, ['error' => 'not found']);
        }
        $aad = "$name:$version";
        $pt = CryptoUtil::decrypt_secret(
            $row['kek_id'],
            $row['nonce'],
            $row['wrapped_dek'],
            $row['nonce'],
            $row['tag'],
            $row['ciphertext'],
            $aad
        );
        // audit
        $a = $pdo_secrets->prepare('INSERT INTO audit_logs (secret_id, action, actor, details) VALUES (?, ?, ?, ?)');
        $a->execute([$row['id'], 'READ', $actor['sub'], json_encode(['version' => $version])]);
        api_response(200, ['name' => $name, 'version' => $version, 'secret' => $pt]);
    }
}

// fallback
api_response(404, ['error' => 'not found']);

?>