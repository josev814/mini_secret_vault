<?php
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../private/CryptoUtil.php';

class CryptoUtilTest extends TestCase {
    
    public function testEncryptDecrypt() {
        $plaintext = "secret_data";
        [$dek_nonce, $dek_wrapped, $nonce, $tag, $ciphertext, $kek_id] = CryptoUtil::encrypt_secret($plaintext);
        $decrypted = CryptoUtil::decrypt_secret($kek_id, $dek_nonce, $dek_wrapped, $nonce, $tag, $ciphertext);
        $this->assertEquals($plaintext, $decrypted);
    }
}