# Rotate TLS and Service Account Keys

Refer to
[REST, MCP Endpoints, and Environment](../../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
and
[Configuration Schema and Profiles](../../03-reference/configuration/config-schema-and-profiles.md)
before you rotate credentials.

## Prerequisites

1. Hold an active `admin` Personal Access Token (`gat_pat_...`).
2. Identify the target Service Account `id` or Personal Access Token `id` to rotate or revoke.
3. Prepare access to client secret vaults that consume `gat_svc_` keys.

## Safety Instructions

**CAUTION:** Store new `gat_pat_` tokens and `gat_svc_` keys only in an encrypted secrets manager.
Plaintext secrets in shell history or YAML files expose host command execution.

**CAUTION:** Update downstream clients immediately after `POST /api/v1/auth/service-accounts/rotate`.
Key rotation invalidates the previous `gat_svc_` secret at once with HTTP `401`.

## Procedure

1. Inspect the active TLS certificate expiration window and SHA-256 fingerprint with `GET /api/v1/tls/info`:

   ```bash
   curl -k https://localhost:8080/api/v1/tls/info \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```

2. Trigger zero-downtime ECDSA P-256 certificate rotation with `POST /api/v1/tls/renew`:

   ```bash
   curl -k -X POST https://localhost:8080/api/v1/tls/renew \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```

3. Download the rotated public PEM certificate if clients pin leaf certificates:

   ```bash
   curl -k https://localhost:8080/api/v1/tls/certificate -o server.crt
   ```

4. List registered Service Accounts with `GET /api/v1/auth/service-accounts` and copy the target `id`:

   ```bash
   curl -k https://localhost:8080/api/v1/auth/service-accounts \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```

5. Rotate the target Service Account API key with `POST /api/v1/auth/service-accounts/rotate`:

   ```bash
   curl -k -X POST https://localhost:8080/api/v1/auth/service-accounts/rotate \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     -d "{\"id\":\"${SA_ID}\"}"
   ```

6. Save the returned `"api_key"` (`gat_svc_...`) in the client secrets vault and update the `X-Service-Key` header.
7. List Personal Access Tokens and revoke stale tokens with `DELETE /api/v1/auth/tokens?id={id}`:

   ```bash
   curl -k https://localhost:8080/api/v1/auth/tokens \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   curl -k -X DELETE "https://localhost:8080/api/v1/auth/tokens?id=${TOK_ID}" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```

**NOTE:** `CertManager` swaps the active certificate under `sync.RWMutex` with zero HTTP listener restart.
Private key files keep strict `0600` permissions on disk.

## Verification

1. Call `GET /api/v1/tls/info` and confirm a new `serial_number` and `fingerprint_sha256`.
2. Call `GET /api/v1/auth/me` with the old `gat_svc_` key and confirm HTTP `401`.
3. Call `GET /api/v1/auth/me` with the new `gat_svc_` key and confirm HTTP `200`:

   ```bash
   curl -k https://localhost:8080/api/v1/auth/me -H "X-Service-Key: ${NEW_SVC_KEY}"
   ```

4. Query `GET /api/v1/audit/logs?category=tls` and `GET /api/v1/audit/logs?category=auth` for `tls.renew` and
   `service_account.rotate` records.

## Rollback

If rotation breaks client connectivity, do these steps:

1. If clients reject a new custom PKI certificate, restore `cert_file` and `key_file` and restart `go-admin-tool`.
2. If a client lost the new `gat_svc_` key, run `POST /api/v1/auth/service-accounts/rotate` and update the vault.
3. Run `GET /api/v1/audit/verify` and confirm `"valid": true`.

## Related Documentation

- Reference: [REST, MCP Endpoints, and Environment](../../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
- Reference: [Configuration Schema and Profiles](../../03-reference/configuration/config-schema-and-profiles.md)
- Explanation:
  [ADR-001: Zero-Trust Execution and Bastion](../../04-explanation/design-decisions/adr-001-zero-trust-execution-and-bastion.md)
- Explanation:
  [Concurrency, Timeouts, and Cryptographic Chains](../../04-explanation/deep-dives/concurrency-timeouts-and-cryptographic-chains.md)
