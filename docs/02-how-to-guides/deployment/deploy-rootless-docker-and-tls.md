# Deploy Rootless Docker and TLS

Refer to
[Configuration Schema and Profiles](../../03-reference/configuration/config-schema-and-profiles.md)
and
[REST, MCP Endpoints, and Environment](../../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
before you deploy the container.

## Prerequisites

1. Make sure that you have `sudo` or root access on the Linux host.
2. Make sure that Docker Engine or Podman is active on the host.
3. Make sure that TCP port `8080` is open on the target network interface.

## Safety Instructions

**CAUTION:** Do not run the container as UID `0` or set `userns: "host"`.
Root execution breaks process isolation and fails sandbox validation.

**CAUTION:** Set `auth.require_auth: true` and `tls.enabled: true` in production configuration files.
Unauthenticated HTTP mode exposes remote command execution and tokens in cleartext.

## Procedure

1. Create persistent host directories for configuration, certificates, SQLite data, plugins, and secure files:

   ```bash
   sudo mkdir -p /opt/api-executor/{certs,data,plugins,secure_files}
   ```

2. Set directory ownership to non-root UID `10001` and GID `10001`:

   ```bash
   sudo chown -R 10001:10001 /opt/api-executor
   ```

3. Create `/opt/api-executor/config.yaml` with TLS `1.3`, strict authentication, and rootless sandbox enforcement:

   ```yaml
   version: "2.2.0"

   server:
     port: 8080
     host: "0.0.0.0"
     tls:
       enabled: true
       auto_generate: true
       cert_file: "/app/certs/server.crt"
       key_file: "/app/certs/server.key"
       organization: "API Executor Production"
       validity_days: 365
       min_version: "1.3"
       hosts:
         - "localhost"
         - "127.0.0.1"

   database:
     path: "/app/data/history.db"

   file_server:
     enabled: true
     secure_dir: "/var/log/secure_files"

   auth:
     enabled: true
     require_auth: true
     bootstrap_username: "admin"
     bootstrap_password: "replace-with-strong-password"

   sandbox:
     enabled: true
     enforce_non_root: true
     uid: 10001
     gid: 10001
     userns: "keep-id"
     drop_privileges: true
     no_new_privileges: true
     drop_caps: true
   ```

4. Optional: Add an `otlp_export` block to `/opt/api-executor/config.yaml` to push OTLP/HTTP metrics:

   ```yaml
   otlp_export:
     enabled: true
     endpoint: "https://otel-collector.internal:4318/v1/metrics"
     push_interval: "30s"
     timeout: "10s"
   ```

5. Restrict permissions on `/opt/api-executor/config.yaml` to owner read and write:

   ```bash
   sudo chmod 0600 /opt/api-executor/config.yaml
   sudo chown 10001:10001 /opt/api-executor/config.yaml
   ```

6. Pull the latest published multi-architecture image from Docker Hub:

   ```bash
   docker pull jmrenouard/api_executor:v2.1.0
   ```

7. Start the `api-executor` container with dropped capabilities, `no-new-privileges`, and mounted volumes:

   ```bash
   docker run -d \
     --name api-executor \
     --restart unless-stopped \
     -p 8080:8080 \
     -u 10001:10001 \
     -e CONFIG_PATH=/app/config.yaml \
     -e TZ=UTC \
     -v /opt/api-executor/config.yaml:/app/config.yaml:ro \
     -v /opt/api-executor/certs:/app/certs \
     -v /opt/api-executor/data:/app/data \
     -v /opt/api-executor/plugins:/app/plugins:ro \
     -v /opt/api-executor/secure_files:/var/log/secure_files \
     --security-opt no-new-privileges:true \
     --cap-drop ALL \
     jmrenouard/api_executor:v2.1.0
   ```

**NOTE:** The container creates `/app/certs/server.crt` and `/app/certs/server.key` (`0600`) at startup.
Use your own PEM files inside `/opt/api-executor/certs` to stop self-signed certificate generation.
Release tag `v2.1.0` is the latest published container image.
Branch `main` builds version `2.2.0` from source.

## Verification

1. Check the container health status and confirm `"healthy"`:

   ```bash
   docker inspect --format='{{json .State.Health.Status}}' api-executor
   ```

2. Query the public liveness probe `/health` and readiness probe `/readyz` through HTTPS:

   ```bash
   curl -sk https://localhost:8080/health
   curl -sk https://localhost:8080/readyz
   ```

3. Confirm `"status": "ok"` on `/health` and `"status": "ready"` on `/readyz`.

4. Query the public version endpoint through HTTPS:

   ```bash
   curl -k https://localhost:8080/api/v1/version
   ```

5. Authenticate as `admin` and inspect `/api/v1/tls/info`:

   ```bash
   TOKEN=$(curl -sk -X POST https://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"replace-with-strong-password"}' | jq -r '.token')
   curl -sk https://localhost:8080/api/v1/tls/info -H "Authorization: Bearer ${TOKEN}"
   ```

6. Confirm `"enabled": true` and `"min_version": "1.3"` in the JSON response.

## Rollback

If an error occurs after deployment, do these steps:

1. Stop and remove the `api-executor` container:

   ```bash
   docker stop api-executor && docker rm api-executor
   ```

2. Restore the previous `/opt/api-executor/config.yaml` and `/opt/api-executor/certs` backup files.
3. Start the previous image tag with the same UID `10001` volume mounts.
4. Query `/api/v1/version` and confirm HTTP `200`.

## Related Documentation

- Reference: [Configuration Schema and Profiles](../../03-reference/configuration/config-schema-and-profiles.md)
- Reference: [REST, MCP Endpoints, and Environment](../../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
- Explanation:
  [Zero-Trust MCP Bastion Topology](../../04-explanation/architecture-overview/zero-trust-mcp-bastion-topology.md)
- Explanation:
  [ADR-001: Zero-Trust Execution and Bastion](../../04-explanation/design-decisions/adr-001-zero-trust-execution-and-bastion.md)
