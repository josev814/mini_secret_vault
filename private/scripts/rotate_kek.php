<?php
use Vault\CryptoUtil;
use Vault\Db;

$pdo = Db::get(getenv('SECRETS_DB_HOST'),getenv('SECRETS_DB'), getenv('SECRETS_DB_USER'), getenv('SECRETS_DB_PASS'));
$sth = $pdo->prepare('SELECT id, wrapped_dek, nonce, kek_id FROM secrets');
$sth->execute();
$rows = $sth->fetchAll(PDO::FETCH_ASSOC);

foreach ($rows as $r) {
    try {
        // unwrap with stored kek_id; unwrap_dek will throw if that kek_id isn't available
        $dek = CryptoUtil::unwrap_dek($r['kek_id'], $r['nonce'], $r['wrapped_dek']);
    } catch (Exception $e) {
        // fallback: try all known KEKs (if unwrap_dek supports it). If that fails, skip and log.
        echo "Failed unwrap for id {$r['id']}: {$e->getMessage()}\n";
        continue;
    }

    // Now wrap with current primary via wrap_dek
    [$new_nonce, $new_wrapped, $new_kek_id] = CryptoUtil::wrap_dek($dek);

    $upd = $pdo->prepare('UPDATE secrets SET wrapped_dek = ?, nonce = ?, kek_id = ? WHERE id = ?');
    $upd->execute([$new_wrapped, $new_nonce, $new_kek_id, $r['id']]);

    sprintf("Rewrapped secret id %s to KEK %s",
        $r['id'],
        $new_kek_id
    );
}
