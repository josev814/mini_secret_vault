# Mini Secret Vault (Plain PHP + Multi-KEK + Separate Secrets DB)

A lightweight secret management service in **plain PHP** using **MySQL**, supporting:

- Multi-KEK envelope encryption
- JWT authentication with refresh and revocation tokens
- Audit logging of all secret accesses
- Separate databases for secrets and app data
- Swagger UI for API documentation
- Recovery using backup KEKs
- Automated unit tests via PHPUnit
- GitHub Actions workflow for CI

---

## Features

- Secrets Management: Store, retrieve, and version secrets securely.
- Multi-KEK Support: Multiple key encryption keys for backup/recovery.
- JWT Auth: Issue, refresh, and revoke tokens securely.
- Audit Logging: Track all access events.
- Separate Databases: App DB for users/tokens, Secrets DB for ciphertext and audit logs.
- Swagger UI: Dynamic API documentation via CDN.
- Automated Testing: Unit tests for core components.
- CI/CD: GitHub Actions workflow to run tests on PHP 8.0–8.4.

---

## Requirements

- PHP 8.0+
- MySQL 8+
- Composer (optional, for PHPUnit)
- Web server (Apache, Nginx, or PHP built-in)
- OpenSSL PHP extension

---

## Installation

1) Clone the repository:
```bash
git clone <repo-url> mini-secret-vault
cd mini-secret-vault
```

2) Set up two MySQL databases:
- `app_db`: users, refresh tokens, revoked JWTs.
- `secrets_db`: encrypted secrets, audit logs.

3) Apply the SQL schema migrations.

4) Configure environment variables:
```bash
MASTER_KEKS_JSON='[{"id":"primary","b64":"<base64_key>"},{"id":"backup","b64":"<base64_key>"}]'
MASTER_KEK_PRIMARY_ID='primary'
JWT_SECRET='<strong_jwt_secret>'
```

5) Update index.php with $pdo_app and $pdo_secrets connection details.
6) Install Composer dependencies:
```bash
composer install
```

## Installation (Docker Variation)
```bash
docker compose up --build -d
docker composer exec app bash 'php init_db.php'

```


7) Start the PHP server (development mode):
```
php -S 0.0.0.0:8080
```

---

### Default Creds
Automatically seeded if no users exist.
Username: `admin`
Password: `this is in the output of init_db` (**change immediately**)
---

## Swagger UI

- Accessible at: http://localhost:8080/docs
- Swagger JSON endpoint: http://localhost:8080/docs/swagger.json
- Uses CDN for Swagger UI, no extra setup needed.

---

## Managing KEKs
### Add a KEK
1) Generate a new 32-byte KEK and base64 encode it.
```bash
php -r "echo base64_encode(random_bytes(32));"
```
2) Add to `MASTER_KEKS_JSON` with a unique id.
3) Update `MASTER_KEK_PRIMARY_ID` if new secrets should use it by default.
#### Example MASTER_KEKS_JSON
```bash
MASTER_KEKS_JSON='[
  {"id":"k_2025_09_primary","b64":"<base64-of-32-bytes>"},
  {"id":"k_2024_12_backup","b64":"<base64-of-32-bytes>"}
]'
MASTER_KEK_PRIMARY_ID=k_2025_09_primary
```

### Remove a KEK
1) Ensure no existing secrets depend on the KEK.
2) Remove it from MASTER_KEKS_JSON.

### Recovery with Backup KEKs
- Each secret stores its kek_id.
- If the primary KEK is lost, backup KEKs in MASTER_KEKS_JSON can decrypt secrets.
- Keep backup KEKs secure; do not commit to version control.

---

## API Endpoints
### Authentication
- POST `/login` -> returns JWT + refresh token
- POST `/token/refresh` -> refresh JWT
- POST `/logout` -> revoke token
### Secrets
- POST `/secret` -> store a secret
- GET `/secret/{name}` -> retrieve latest version
- GET `/secret/{name}/{version}` -> retrieve specific version
### Swagger Docs
- `/docs` -> interactive API docs
- `/docs/swagger.json` -> JSON schema

## Example Usage
### Login to get a token:
```bash
curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password_from_init_db>"}' | jq
```
Copy the returned token.

### Use the token to create a secret:
```bash
curl -s -X POST http://localhost:8080/secret \
  -H "Authorization: Bearer <token>" \
  -H 'Content-Type: application/json' \
  -d '{"name":"app/payment/stripe","secret":"sk_test_ABC"}' | jq
```

### Read the secret:
```bash
curl -s -X GET http://localhost:8080/secret/app%2Fpayment%2Fstripe \
  -H "Authorization: Bearer <token>" | jq
```
Visit docs in browser: open http://localhost:8080/docs. The page is protected; paste your token into the Authorize button in Swagger UI.

## Cleanup Script
Run cleanup.php via CLI or cron to:
- Remove expired refresh tokens and revoked JWTs from app DB
- Optionally remove old audit logs from secrets DB
```bash
php cleanup.php
```

---

## PHPUnit Tests
- Tests located in tests/ for CryptoUtil, JwtUtil, RefreshTokenUtil.
- Run locally with:
```bash
vendor/bin/phpunit --configuration phpunit.xml
```

## GitHub Actions
- Workflow: `.github/workflows/phpunit.yml`
- Runs on push and pull request
- Matrix test against PHP 8.0, 8.1, 8.2, 8.3, 8.4
- Automatically runs all PHPUnit tests

## Notes
- Store KEKs in environment variables or KMS/HSM.
- Secrets DB is isolated for security.
- Regular backups and monitoring recommended.
- Environment configuration is critical for multi-KEK and recovery functionality.
