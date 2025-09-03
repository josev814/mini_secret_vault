<?php
require_once __DIR__ . '/../Db.php';
use Vault\Db;

$schemas = [];
foreach(scandir(__DIR__ . '/../../db') as $entry){
    if (preg_match('/schema.sql$/', $entry)){
        $schemas[] = $entry;
    }
}
if (empty($schemas)){
    die('Failed to retrieve schemas');
}

$pdo_app = Db::get(getenv('USER_DB_HOST'),getenv('USER_DB'), getenv('USER_DB_USER'), getenv('USER_DB_PASS'));
$pdo_secrets = Db::get(getenv('SECRETS_DB_HOST'),getenv('SECRETS_DB'), getenv('SECRETS_DB_USER'), getenv('SECRETS_DB_PASS'));

// create tables
foreach($schemas as $schema){
    $data = file_get_contents(__DIR__ . '/../../db/' . $schema);
    if (preg_match('/app_/', $schema)){
        $pdo_app->exec($data);
    } elseif (preg_match('/secrets_/', $schema)){
        $pdo_secrets->exec($data);
    } else {
        new Exception('Unhandled Schema: ' . $schema);
    }
}

// seed admin if no users
$stmt = $pdo_app->query("SELECT COUNT(*) as c FROM users");
$c = $stmt->fetch()['c'] ?? 0;
if ($c > 0) {
    new Exception("Users already exist");
}

$password = base64_encode(random_bytes(32));
$hash = password_hash($password, PASSWORD_BCRYPT);
$ins = $pdo->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
$ins->execute(['admin', $hash]);
sprintf(
    '{"User":"%s","Password":"%s"}',
    'admin',
    $password
);
