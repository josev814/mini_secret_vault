<?php
use PHPUnit\Framework\TestCase;
use Vault\CryptoUtil;

class CryptoUtilTest extends TestCase {
    
    public function testEncryptDecrypt() {
        $plaintext = "secret_data";
        [$dek_nonce, $dek_wrapped, $nonce, $tag, $ciphertext, $kek_id] = CryptoUtil::encrypt_secret($plaintext);
        $decrypted = CryptoUtil::decrypt_secret($kek_id, $dek_nonce, $dek_wrapped, $nonce, $tag, $ciphertext);
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testSingleKEKEncryptDecrypt() {
        $json_kek = getenv('MASTER_KEKS_JSON');
        $tmpkek = putenv('MASTER_KEKS_JSON=');
        $plaintext = "secret_data";
        [$dek_nonce, $dek_wrapped, $nonce, $tag, $ciphertext, $kek_id] = CryptoUtil::encrypt_secret($plaintext);
        $decrypted = CryptoUtil::decrypt_secret($kek_id, $dek_nonce, $dek_wrapped, $nonce, $tag, $ciphertext);
        $this->assertEquals($plaintext, $decrypted);
        putenv('MASTER_KEKS_JSON=' . $json_kek);
    }
}