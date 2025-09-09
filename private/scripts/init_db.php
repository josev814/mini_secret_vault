<?php
ini_set('display_errors', '1');
ini_set('output_buffering', '0');
ini_set('implicit_flush', '1');
ob_implicit_flush(true);

require_once __DIR__ . '/../Db.php';
require_once __DIR__ . '/../UserUtil.php';
use Vault\Db;
use Vault\UserUtil;

$schemas = [];
foreach(scandir(__DIR__ . '/../../db') as $entry){
    if (preg_match('/schema.sql$/', $entry)){
        $schemas[] = $entry;
    }
}
if (empty($schemas)){
    die('Failed to retrieve schemas');
}

$pdo_app = Db::get(getenv('APP_DB_HOST'),getenv('APP_DB'), getenv('APP_DB_USER'), getenv('APP_DB_PASS'));
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

$userutil = new UserUtil();
$hash = $userutil->encrypt_password(NULL, true);
$ins = $pdo_app->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
$ins->execute(['admin', $hash]);

$json_data = json_encode([
    'User' => 'admin',
    'Default Password' => $userutil->get_password(),
]) . PHP_EOL;

echo $json_data;