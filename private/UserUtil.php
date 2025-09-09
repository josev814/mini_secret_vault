<?php
namespace Vault;


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
        return true;
    }
}