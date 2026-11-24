# Manage Async Jobs and Presets

Refer to
[REST, MCP Endpoints, and Environment](../../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
and
[Configuration Schema and Profiles](../../03-reference/configuration/config-schema-and-profiles.md)
before you execute these tasks.

## Prerequisites

1. Make sure that `go-admin-tool` is active and reachable through HTTPS.
2. Obtain an `admin` token for preset activation and an `operator` or `admin` token for job calls.
3. Make sure that `command_executor.max_timeout_seconds` covers the longest target job duration.

## Safety Instructions

**CAUTION:** Check queue depth on `/api/v1/jobs/queue` before you submit bulk async jobs.
The priority heap holds at most `1000` jobs and rejects excess requests with HTTP `429`.

**CAUTION:** Set explicit per-job `"timeout"` overrides that stay below `max_timeout_seconds`.
Excessive timeouts return HTTP `400` and stall worker pool slots until cancellation.

## Procedure

1. Optional: Set worker pool, queue capacity, log buffer, and retention limits under `jobs` in `config.yaml`:

   ```yaml
   jobs:
     workers_count: 4
     queue_capacity: 1000
     max_log_bytes: 2097152
     prune_interval: "10m"
     max_job_age: "168h"
     max_retained_jobs: 10000
   ```

2. List available Ubuntu and RedHat OS preset catalogs with `GET /api/v1/presets`:

   ```bash
   curl -k https://localhost:8080/api/v1/presets \
     -H "Authorization: Bearer ${TOKEN}"
   ```

3. Activate the `ubuntu` or `redhat` preset family as `admin` with `POST /api/v1/presets/activate`:

   ```bash
   curl -k -X POST https://localhost:8080/api/v1/presets/activate \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"families":["ubuntu"]}'
   ```

4. Query commands for a named configuration profile with `?profile=` or `X-Config-Profile`:

   ```bash
   curl -k "https://localhost:8080/api/v1/commands?profile=ubuntu" \
     -H "Authorization: Bearer ${TOKEN}"
   ```

5. Submit a prioritized async command job with `POST /api/v1/jobs`:

   ```bash
   curl -k -X POST https://localhost:8080/api/v1/jobs \
     -H "Authorization: Bearer ${TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"type":"command","action":"ubuntu-dpkg-packages","priority":"high","timeout":"30s"}'
   ```

6. Record the returned `job_id`, then poll job status with `GET /api/v1/jobs/{id}`:

   ```bash
   curl -k "https://localhost:8080/api/v1/jobs/${JOB_ID}" \
     -H "Authorization: Bearer ${TOKEN}"
   ```

7. Poll chunked stdout and stderr logs from byte offset `0` until `"eof": true`:

   ```bash
   curl -k "https://localhost:8080/api/v1/jobs/${JOB_ID}/logs?offset=0" \
     -H "Authorization: Bearer ${TOKEN}"
   ```

8. Stream live status and log events with Server-Sent Events (SSE) on `GET /api/v1/jobs/{id}/stream`:

   ```bash
   curl -kN "https://localhost:8080/api/v1/jobs/${JOB_ID}/stream?offset=0" \
     -H "Authorization: Bearer ${TOKEN}"
   ```

9. If you must abort an active or queued job, call `POST /api/v1/jobs/{id}/cancel`:

   ```bash
   curl -k -X POST "https://localhost:8080/api/v1/jobs/${JOB_ID}/cancel" \
     -H "Authorization: Bearer ${TOKEN}"
   ```

**NOTE:** Each `JobLogBuffer` holds up to `2 MiB` of output per job.
When output exceeds `2 MiB`, the response sets `"truncated": true`.
The SSE endpoint emits `status`, `log`, and `done` events and accepts `Last-Event-ID` for stream resume.

## Verification

1. Query `GET /api/v1/jobs/queue` and confirm `workers_active` and `queued_jobs` values:

   ```bash
   curl -k https://localhost:8080/api/v1/jobs/queue \
     -H "Authorization: Bearer ${TOKEN}"
   ```

2. Confirm `status` equals `"completed"` or `"cancelled"` on `GET /api/v1/jobs/{id}`.
3. Query `GET /metrics` and confirm `action_mode_calls_total` with `mode="async"` increments:

   ```bash
   curl -k https://localhost:8080/metrics | grep action_mode_calls_total
   ```

## Rollback

If activated presets or background jobs cause overload, do these steps:

1. Cancel active or queued jobs with `POST /api/v1/jobs/{id}/cancel`.
2. Set `command_executor.enable_os_presets: false` in `config.yaml` if presets must not stay loaded.
3. Restart `go-admin-tool` to reload only explicit `config.yaml` commands.

## Related Documentation

- Reference: [REST, MCP Endpoints, and Environment](../../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
- Reference: [Configuration Schema and Profiles](../../03-reference/configuration/config-schema-and-profiles.md)
- Explanation:
  [Concurrency, Timeouts, and Cryptographic Chains](../../04-explanation/deep-dives/concurrency-timeouts-and-cryptographic-chains.md)
- Explanation:
  [Zero-Trust MCP Bastion Topology](../../04-explanation/architecture-overview/zero-trust-mcp-bastion-topology.md)
