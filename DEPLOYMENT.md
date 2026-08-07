# Trident Deployment Guide

## 1. Single-Instance Deployment

### Architecture

```
        ┌──────────┐
 App ──▶│ Trident  │──▶ Writer (Primary)
 App ──▶│          │──▶ Reader 1
 App ──▶│          │──▶ Reader 2
        └──────────┘──▶ Analytics
```

A single Trident process listens on `proxy.listen_addr` (e.g., `0.0.0.0:6432`). Applications connect to it as they would a regular PostgreSQL server. This is the only fully verified deployment topology.

### Starting Trident

Set `TRIDENT_CONFIG` to specify the config file path (defaults to `config.yaml` in the working directory).

| Method | Use Case | Reference |
|--------|----------|-----------|
| Systemd | Bare metal / VM | `deploy/systemd/` |
| Docker Compose | Local dev / smoke testing | `docker-compose.yml` |
| Kubernetes | Production clusters | `deploy/k8s/` |

All three share the same binary/image; they differ only in process management and config injection.

### Availability Boundary

- Trident has no built-in process-level HA (no clustering, leader election, or automatic failover between proxy instances). Rely on systemd auto-restart, cloud instance recovery, or multi-instance deployment (Section 7).
- Backend-level HA is fully implemented: `HealthChecker` concurrently probes all nodes every `health.check_interval`, with per-node `check_timeout`. Unhealthy nodes are excluded from routing and automatically re-admitted upon recovery.

## 2. Authentication

### Backend Password Sources

`NodeConfig.password` is optional. Resolution order:

1. **`${ENV_VAR}` placeholder** — resolved from process environment at load time. Missing variable causes startup failure.
2. **Omit the field** — looked up from `.pgpass` file (`PGPASSFILE` env or `~/.pgpass`), same format as libpq.
3. **Plaintext** — only for local testing.

Startup fails if no password can be resolved for any node.

### Supported Auth Mechanisms

Cleartext, MD5, and SCRAM-SHA-256 are supported for backend connections and health probes.

### Client-Side Security

Trident currently accepts client connections in **trust mode** (no client password validation). Production deployments must:
- Restrict `proxy.listen_addr` to trusted networks
- Use firewall/security groups to control access
- Place an authenticated TCP proxy in front if client identity verification is needed

### Backend SSL

Configure `ssl_mode: require` on nodes to enable TLS connections to backends.

## 3. Logging

### Configuration

```yaml
logging:
  level: info
  query_trace: false        # Log every Simple Query statement at INFO level
  slow_query: 1000          # Threshold in ms; logs at WARN level
  dir: /var/log/trident     # Optional: enable file logging (also keeps stdout)
  file_prefix: trident.log
  max_files: 14
  rotation: daily           # daily | hourly | size_based
  max_file_size_mb: 100     # Only for size_based rotation
```

### Behavior

- Without `dir`: logs to stdout only (suitable for containers).
- With `dir`: logs to both stdout and rolling files.
- Rotation strategies:
  - `daily` — one file per day. No per-file size limit.
  - `hourly` — one file per hour.
  - `size_based` — rotates at `max_file_size_mb`. Use this for strict file size caps.
- Retention (`max_files`) is enforced continuously, not just at startup.
- For Docker/K8s: prefer stdout-only logging and use container log drivers or collection agents.

### Privacy Note

Both `query_trace` and slow query logging include full SQL text. Simple Query statements contain literal parameter values (not parameterized). Evaluate compliance requirements before enabling.

## 4. Monitoring & Admin Interface

Disabled by default. Enable:

```yaml
admin:
  enabled: true
  listen_addr: "127.0.0.1:9090"
```

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Returns 200 if at least one healthy Writer exists; 503 otherwise. Use as k8s readiness/liveness probe. |
| `GET /metrics` | Prometheus text format metrics |
| `GET /client-stats` | Per-IP connection statistics (JSON) |
| `POST /reload` | Trigger hot reload |
| `GET/POST/DELETE /custom-rules` | Manage custom routing rules |
| `GET /` | Embedded web management console |

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trident_connections_accepted_total` | counter | Total accepted client connections |
| `trident_connections_rejected_total` | counter | Connections rejected due to `max_clients` |
| `trident_active_connections` | gauge | Currently active client connections |
| `trident_routing_decisions_total{target}` | counter | Routing decisions by target (writer/reader/analytics) |
| `trident_health_checks_total{node_id,result}` | counter | Health check results per node |
| `trident_pool_active_connections{node_id}` | gauge | Active backend connections per node |
| `trident_pool_max_size{node_id}` | gauge | Pool capacity per node |
| `trident_pool_checkouts_total{node_id}` | counter | Total connection checkouts from the pool |
| `trident_pool_connections_established_total{node_id}` | counter | New backend connections created |
| `trident_pool_exhausted_total{node_id}` | counter | Pool exhaustion events (client gets SQLSTATE 53300) |
| `trident_node_replication_lag_ms{node_id}` | gauge | Replication lag per Reader/Analytics node |
| `trident_query_duration_ms{target}` | histogram | Per-statement latency (Simple Query only) |
| `trident_slow_queries_total` | counter | Statements exceeding `slow_query` threshold |
| `trident_client_distinct_active_ips` | gauge | Distinct client IPs with active connections |

**Note**: Query duration and slow query tracking currently only cover Simple Query protocol. Extended Query (Parse/Bind/Execute) statements are not instrumented.

### Security

The admin interface has **no authentication**. Always:
- Bind to a private/loopback address
- Restrict network access via firewall/security groups
- Never expose to the public internet

## 5. Hot Reload

### Reloadable Parameters

All under `routing`:
```
enable_transaction_split, split_respects_consistency,
enable_hint_routing, enable_cost_routing, cost_threshold,
writer_readable, analytics_patterns, custom_rules, default_consistency
```

### Not Reloadable (requires restart)

`proxy.*`, `nodes`, `pool.*`, `health.*`, `admin.*`, `logging.*`, `lsn_tracking.*`, `routing.load_balance_strategy`

### Trigger Methods

```bash
kill -HUP <pid>
# or
systemctl reload trident
# or
curl -X POST http://127.0.0.1:9090/reload
```

Reload is atomic: if the new config fails validation, the old config remains in effect.

## 6. Custom Routing Rules

Override routing for specific tables or functions:

```yaml
routing:
  custom_rules:
    - _name: sensitive_table
      _type: t          # t=table, f=function
      rw_mode: w        # w=writer-only, r=reader-eligible
    - _name: my_reporting_func
      _type: f
      rw_mode: r
```

### Dynamic Management (via admin API)

```bash
# List rules
curl http://127.0.0.1:9090/custom-rules

# Add/update rule
curl -X POST http://127.0.0.1:9090/custom-rules \
  -H 'content-type: application/json' \
  -d '{"_name":"sensitive_table","_type":"t","rw_mode":"w"}'

# Delete rule
curl -X DELETE http://127.0.0.1:9090/custom-rules \
  -H 'content-type: application/json' \
  -d '{"_name":"sensitive_table","_type":"t"}'
```

API changes are in-memory only. A file-based reload (`SIGHUP`/`POST /reload`) replaces them with file contents. For persistence, edit the config file.

### Priority

Hints > Custom Rules > Cost-based routing. Rules only affect statements that would otherwise be classified as readable.

## 7. Multi-Instance Deployment

### Architecture

```
        ┌────────────┐      ┌──────────┐
 App ──▶│  TCP LB    │─┬───▶│ Trident-1│──▶ Writer/Reader/...
 App ──▶│  (L4)      │ │    └──────────┘
        └────────────┘ └───▶┌──────────┐
                             │ Trident-2│──▶ Writer/Reader/...
                             └──────────┘
```

Requires an **L4/TCP load balancer** (LVS, HAProxy TCP mode, NLB). L7/HTTP LBs cannot parse PostgreSQL wire protocol.

### Known Limitations

| Capability | Single Instance | Multi-Instance |
|-----------|----------------|----------------|
| Read/write splitting, pooling, health checks | ✓ Correct | ✓ Correct (each independent) |
| `Session` consistency | ✓ Correct | ✓ Correct (TCP connection affinity) |
| `Global` consistency | ✓ Correct | ✗ **Incorrect** — LSN tracker is per-process |
| `Eventual` consistency | ✓ Correct | ✓ Correct |
| CANCEL requests | ✓ Correct | ⚠ **May silently fail** — LB may route to wrong instance |
| Pool capacity planning | `max_pool_size` per node | `instances × max_pool_size` per node |

### Recommendations

- Use `Session` or `Eventual` consistency in multi-instance deployments
- Enable source-IP session stickiness on the TCP LB to mitigate CANCEL issues
- Size backend `max_connections` for total pool capacity across all instances
- Trigger reload independently on each instance (not broadcast)

## 8. Transaction Splitting & Connection Pool

### Transaction Split Behavior

With `enable_transaction_split: true`:
1. `BEGIN` is acknowledged locally (no backend connection acquired)
2. First SQL statement determines routing target (Reader for reads, Writer for writes)
3. If a write appears after reads on Reader: Reader transaction is rolled back, a new transaction begins on Writer
4. Connection stays pinned until `COMMIT`/`ROLLBACK`

**Important**: Reader→Writer upgrade does not replay previous reads or inherit MVCC snapshot. Applications requiring single-snapshot read-then-write must disable transaction splitting.

### Pool Parameters

All per-process, per-node:

| Parameter | Description |
|-----------|-------------|
| `max_pool_size` | Max concurrent connections to this node. Exhaustion → SQLSTATE 53300 |
| `min_pool_size` | Pre-warmed connections at startup. Failure aborts startup |
| `connection_timeout` | Max time to establish + authenticate. Timeout → SQLSTATE 08001 |
| `max_idle_time` | Max idle time before connection is discarded (lazy check) |
| `max_lifetime` | Max connection age from creation (lazy check) |

Idle/lifetime limits are checked lazily on acquisition. Active, pinned, or in-transaction connections are never interrupted.

## 9. LSN Tracking Modes

Controls how Trident obtains write LSN positions for consistency checks. **Restart-only** — not hot-reloadable.

```yaml
lsn_tracking:
  mode: auto   # auto | pipeline | extension | aurora_write_forwarding
```

| Mode | Requirements | Overhead | Description |
|------|-------------|----------|-------------|
| `pipeline` | None (works with any PostgreSQL) | ~tens of μs per write | Appends internal `SELECT pg_current_wal_lsn()` in same write batch |
| `extension` | `pg_lsn_track` extension on backend | Zero | Reads LSN from `ParameterStatus` GUC report |
| `auto` | None | Same as pipeline until extension detected | Starts as pipeline; switches to extension if GUC report observed |
| `aurora_write_forwarding` | Aurora with Write Forwarding enabled; `pool.mode: session`; ≥1 reader node | N/A | No LSN tracking; all SQL goes to one pinned Reader; writes forwarded by Aurora |

### Extension Mode Setup (`pg_lsn_track`)

1. Install the `pg_lsn_track` extension on all Writer nodes:
   ```
   shared_preload_libraries = 'pg_lsn_track'
   ```
2. Configure Trident:
   ```yaml
   lsn_tracking:
     mode: extension      # or 'auto' for graceful fallback
     extension:
       guc_name: "pg_lsn_track.last_commit_lsn"
   ```
3. The extension reports the commit LSN via a GUC (`pg_lsn_track.last_commit_lsn`) that emits a `ParameterStatus` message after each committed write transaction. Trident captures this value, suppresses it from the client, and uses it for session/global consistency checks — zero overhead compared to the pipeline approach.

### Choosing a Mode

| Scenario | Recommended |
|----------|-------------|
| Standard PostgreSQL / Aurora without Write Forwarding | `auto` or `pipeline` |
| Backend has LSN-reporting extension installed | `extension` or `auto` |
| Aurora with Write Forwarding enabled + acceptable write latency + session pool mode | `aurora_write_forwarding` |
| Write-latency-sensitive or needs SERIALIZABLE | `pipeline` or `extension` (direct Writer path) |
