<?php
namespace Vault;

require_once 'TotpUtil.php';

class UserUtil {

    private string $password = '';

    public function encrypt_password($password, $init=false){
        if($init){
            $password = base64_encode(random_bytes(32)); //randomize the password, since init
            $this->password = $password;
        }
        $hash = password_hash($password, PASSWORD_BCRYPT);
        return $hash;
    }

    public function get_password(){
        return $this->password;
    }

    public function validate_user($username, $password, \PDO $pdo_app){
        $stmt = $pdo_app->prepare('SELECT * FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        if (!$user || !password_verify($password, $user['password_hash'])) {
            return false;
        }
        return $user;
    }

    /**
     * Check if user has TOTP enabled
     * @param string $username
     * @param \PDO $pdo_app
     * @return bool True if TOTP is enabled
     */
    public static function isTotpEnabled($username, \PDO $pdo_app): bool {
        $stmt = $pdo_app->prepare('SELECT totp_enabled FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $result = $stmt->fetch();
        return $result && (bool)$result['totp_enabled'];
    }

    /**
     * Generate TOTP setup data (secret and backup codes)
     * @param string $username
     * @return array Array with 'secret', 'provisioning_uri', and 'backup_codes'
     */
    public static function generateTotpSetup($username): array {
        $secret = TotpUtil::generateSecret();
        $provisioning_uri = TotpUtil::getProvisioningUri($secret, $username);
        $backup_codes = self::generateBackupCodes();

        return [
            'secret' => $secret,
            'provisioning_uri' => $provisioning_uri,
            'backup_codes' => $backup_codes,
        ];
    }

    /**
     * Generate backup codes for account recovery (one-time use)
     * @param int $count Number of codes to generate
     * @return array Array of backup codes
     */
    public static function generateBackupCodes(int $count = 10): array {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = bin2hex(random_bytes(4)); // 8-char hex codes
        }
        return $codes;
    }

    /**
     * Verify TOTP code or backup code
     * @param string $username
     * @param string $code Either a 6-digit TOTP code or an 8-char backup code
     * @param \PDO $pdo_app
     * @return bool True if verification successful
     */
    public static function verifyTotp($username, $code, \PDO $pdo_app): bool {
        $stmt = $pdo_app->prepare('SELECT totp_secret, totp_backup_codes FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if (!$user) {
            return false;
        }

        // Try TOTP first
        if (TotpUtil::verify($user['totp_secret'], $code)) {
            return true;
        }

        // Try backup code
        $backup_codes = json_decode($user['totp_backup_codes'], true) ?? [];
        if (in_array($code, $backup_codes, true)) {
            // Remove used backup code
            $backup_codes = array_diff($backup_codes, [$code]);
            $stmt = $pdo_app->prepare('UPDATE users SET totp_backup_codes = ? WHERE username = ?');
            $stmt->execute([json_encode(array_values($backup_codes)), $username]);
            return true;
        }

        return false;
    }

    /**
     * Enable TOTP for a user
     * @param string $username
     * @param string $secret The TOTP secret to save
     * @param \PDO $pdo_app
     * @return void
     */
    public static function enableTotp($username, $secret, \PDO $pdo_app): void {
        $backup_codes = self::generateBackupCodes();
        $stmt = $pdo_app->prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_backup_codes = ? WHERE username = ?');
        $stmt->execute([$secret, json_encode($backup_codes), $username]);
    }

    /**
     * Disable TOTP for a user
     * @param string $username
     * @param \PDO $pdo_app
     * @return void
     */
    public static function disableTotp($username, \PDO $pdo_app): void {
        $stmt = $pdo_app->prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_backup_codes = NULL WHERE username = ?');
        $stmt->execute([$username]);
    }
}