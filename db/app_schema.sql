CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active TINYINT DEFAULT 1
);

CREATE TABLE refresh_tokens (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  token VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  replaced_by BIGINT NULL,
  revoked_at DATETIME NULL,
  INDEX(user_id)
);

CREATE TABLE revoked_jtis (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  jti VARCHAR(128) NOT NULL UNIQUE,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX revoked_jti_uq ON revoked_tokens (jti);
CREATE INDEX refresh_token_token_idx ON refresh_tokens (token);
