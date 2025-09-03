<?php
<?php
require_once 'Db.php';
require_once 'CryptoUtil.php';
require_once 'JwtUtil.php';

$pdo = Db::get('apphost','app', 'user', 'pass');
$pdo_secrets = Db::get('secretshost','secrets', 'user', 'pass');
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// helper: get Authorization bearer
function get_bearer_token() {
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['Authorization'] ?? null;
    if (!$hdr) return null;
    if (preg_match('/Bearer\s+(\S+)/', $hdr, $m)) return $m[1];
    return null;
}

function require_auth() {
    $token = get_bearer_token();
    if (!$token) {
        http_response_code(401);
        echo json_encode(['error' => 'missing token']);
        exit;
    }
    $payload = JwtUtil::verify($token);
    if (!$payload) {
        http_response_code(401);
        echo json_encode(['error' => 'invalid token']);
        exit;
    }
    return $payload;
}

// POST /login
if ($method === 'POST' && $path === '/login') {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    if (!$user || !password_verify($password, $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(['error' => 'invalid credentials']);
        exit;
    }
    $token = JwtUtil::sign(['sub' => $username], 120);
    echo json_encode(['token' => $token]); exit;
}

// Serve Swagger UI (protected)
if ($method === 'GET' && $path === '/docs') {
    require_auth();
    header('Content-Type: text/html');
    readfile('docs.html');
    exit;
}

// Serve dynamic swagger.json (protected)
if ($method === 'GET' && $path === '/docs/swagger.json') {
    require_auth();
    header('Content-Type: application/json');
    $base = require 'swagger_template.php';
    echo json_encode($base, JSON_PRETTY_PRINT);
    exit;
}

// POST /secret -> create new version
if ($method === 'POST' && $path === '/secret') {
    $actor = require_auth();
    $data = json_decode(file_get_contents('php://input'), true);
    $name = $data['name'] ?? null;
    $secret = $data['secret'] ?? null;
    if (!$name || !$secret) {
        http_response_code(400);
        echo json_encode(['error' => 'name and secret required']);
        exit;
    }

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

    echo json_encode(['status' => 'ok', 'name' => $name, 'version' => $next]);
    exit;
}

// GET /secret/{name} -> latest
if ($method === 'GET' && preg_match('#^/secret/([^/]+)$#', $path, $m)) {
    $actor = require_auth();
    $name = $m[1];
    $stmt = $pdo_secrets->prepare('SELECT * FROM secrets WHERE name = ? ORDER BY version DESC LIMIT 1');
    $stmt->execute([$name]);
    $row = $stmt->fetch();
    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'not found']);
        exit;
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
    echo json_encode(['name' => $name, 'version' => $row['version'], 'secret' => $pt]);
    exit;
}

// GET /secret/{name}/{version}
if ($method === 'GET' && preg_match('#^/secret/([^/]+)/([0-9]+)$#', $path, $m)) {
    $actor = require_auth();
    $name = $m[1]; $version = (int)$m[2];
    $stmt = $pdo_secrets->prepare('SELECT * FROM secrets WHERE name = ? AND version = ? LIMIT 1');
    $stmt->execute([$name, $version]);
    $row = $stmt->fetch();
    if (!$row) { http_response_code(404); echo json_encode(['error' => 'not found']); exit; }
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
    echo json_encode(['name' => $name, 'version' => $version, 'secret' => $pt]);
    exit;
}

// fallback
http_response_code(404);
echo json_encode(['error' => 'not found']);

?>