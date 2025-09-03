<?php
use Vault\Db;

$schemas = [];
foreach(scandir(__DIR__ . '/../../db') as $entry){
    if (preg_match('/schema\.sql$/', $entry['name'])){
        $schemas[] = $entry;
    }
}
if (empty($schemas)){
    die('Failed to retrieve schemas');
}

$pdo_app = Db::get('apphost','app', 'user', 'pass');
$pdo_secrets = Db::get('secretshost','secrets', 'user', 'pass');

// create tables
foreach($schemas as $schema){
    $data = file_get_contents(__DIR__ . '/../../db/' . $schema['name']);
    if (preg_match('/app_/', $schema['name'])){
        $pdo_app->exec($schema);
    } elseif (preg_match('/secrets_/', $schema['name'])){
        $pdo_secrets->exec($schema);
    } else {
        new Exception('Unhandled Schema: ' . $schema['name']);
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
