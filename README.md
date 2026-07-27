# Trident

A high-performance PostgreSQL read/write splitting proxy with connection pooling, transaction splitting, and multi-level consistency routing.

## Features

- **Read/Write Splitting** — Routes writes to Writer, reads to Reader(s), and analytics queries to dedicated Analytics nodes
- **Transaction Splitting** — Starts read-first transactions on Reader; automatically upgrades to Writer upon encountering a write statement
- **Connection Pooling** — Transaction-level and session-level multiplexing with pre-warmed connections
- **Multi-level Consistency** — Eventual, Session (LSN-based), and Global consistency modes
- **Intelligent Routing** — Hint-based, cost-based, regex pattern matching, and custom per-table/function rules
- **Load Balancing** — Weighted round-robin / least-connections across read replicas
- **Health Checking** — Concurrent probing of all backends with automatic removal/recovery
- **Hot Reload** — Update routing rules via SIGHUP or HTTP without restart
- **Observability** — Prometheus metrics, admin HTTP API, slow query log, client statistics, embedded web console
- **Protocol Support** — Simple Query and Extended Query (Parse/Bind/Execute) protocols, COPY, Cleartext/MD5/SCRAM-SHA-256 auth

## Quick Start

### Build

```bash
cargo build --release
```

### Configure

```bash
cp config.yaml my-config.yaml
# Edit nodes, routing, pool settings as needed
```

Password sources (in priority order):
1. `${ENV_VAR}` placeholder — resolved from environment at startup
2. Omit the field — looked up from `.pgpass` file (same as libpq)
3. Plaintext in config (testing only)

### Run

```bash
# Default: reads config.yaml from current directory
./target/release/trident

# Specify config file
TRIDENT_CONFIG=my-config.yaml ./target/release/trident
```

### Connect

```bash
psql -h 127.0.0.1 -p 6432 -U <username> -d <database>
```

## Configuration Overview

| Section | Description |
|---------|-------------|
| `proxy` | Listen address, max clients |
| `nodes` | Backend nodes (writer/reader/analytics) with weights, auth, SSL mode |
| `routing` | Routing strategy, transaction split, hint/cost routing, analytics patterns, custom rules |
| `lsn_tracking` | LSN consistency tracking mode (auto/pipeline/extension/aurora_write_forwarding) |
| `pool` | Pool mode (transaction/session), sizes, timeouts, lifetime |
| `health` | Check interval, timeout, retries |
| `logging` | Log level, query trace, slow query threshold, file rotation |
| `admin` | Admin HTTP endpoint (metrics/healthz/reload/console) |

See [DEPLOYMENT.md](DEPLOYMENT.md) for full configuration reference, deployment guides, and operational details.

## Performance

Benchmarked against Aurora PostgreSQL 17.7 (1 Writer + 1 Reader, db.r6g.large), pgbench scale=100 (10M rows), transaction splitting enabled, 30s per test, 50 clients.

### TPC-B Mixed Read/Write (UPDATE + SELECT + INSERT)

| Clients | Direct Aurora | Via Trident | Difference |
|---------|--------------|-------------|------------|
| 10      | 707 TPS / 14.1ms | 819 TPS / 12.2ms | **+16% (Proxy faster)** |
| 50      | 2,889 TPS / 17.2ms | 2,750 TPS / 18.1ms | -5% |
| 100     | 3,917 TPS / 25.1ms | 3,315 TPS / 30.0ms | -15% |

### Read-Only SELECT (-S)

| Clients | Direct Aurora | Via Trident | Difference |
|---------|--------------|-------------|------------|
| 10      | 9,043 TPS / 1.1ms | 7,713 TPS / 1.3ms | -15% |
| 50      | 30,854 TPS / 1.5ms | 30,990 TPS / 1.6ms | **≈0% (no overhead)** |
| 100     | 32,448 TPS / 2.3ms | 30,499 TPS / 3.2ms | -6% |

### Detailed Scenarios (50 clients)

| Scenario | Direct Aurora | Via Trident | Difference |
|----------|--------------|-------------|------------|
| Single SELECT (-S) | 30,955 TPS / 1.6ms | 35,398 TPS / 1.4ms | **+14% (Proxy faster)** |
| Autocommit SELECT | 31,103 TPS / 1.6ms | 31,907 TPS / 1.6ms | **≈0%** |
| Transactional read (BEGIN+SELECT+COMMIT) | 13,721 TPS / 3.6ms | 11,571 TPS / 4.3ms | -16% |
| Transaction split (SELECT→UPDATE) | 5,690 TPS / 8.8ms | 4,451 TPS / 11.2ms | -22% |

### Key Takeaways

- **Simple reads have zero or negative overhead**: Autocommit SELECT and single SELECT via proxy match or beat direct connections thanks to connection pool reuse and read/write splitting to Reader
- **Low-concurrency writes benefit from pooling**: At 10 clients, Trident's transaction-mode pool reuse outperforms direct connections by 16%
- **Write-heavy overhead 5-15%** at medium-to-high concurrency, proportional to proxy forwarding latency relative to transaction duration
- **Transaction parsing adds 16% cost**: BEGIN/COMMIT boundary detection introduces per-transaction overhead for explicit transactions
- **Transaction split costs 22%**: Mid-transaction Reader→Writer migration has inherent latency from connection switching
- **Cost-based routing has zero steady-state overhead**: EXPLAIN is executed only once per unique query template and cached; subsequent identical query patterns route instantly from cache
- **Connection setup 98% faster**: Direct Aurora SSL handshake ~90ms vs Trident pool reuse ~2ms
- **Zero transaction failures** across all test scenarios

### Consistency Level Impact (50 clients)

| Scenario | Eventual | Session | Global |
|----------|----------|---------|--------|
| Read-only SELECT | 26,419 TPS | 27,549 TPS | 27,476 TPS |
| Autocommit SELECT | 26,715 TPS | 27,081 TPS | 26,919 TPS |
| Transactional read | 8,192 TPS | 8,400 TPS | 8,054 TPS |
| Write-then-read | **9,456 TPS** | **7,586 TPS (-20%)** | **6,533 TPS (-31%)** |
| Mixed TX (UPDATE+SELECT) | 5,284 TPS | 5,183 TPS | 5,231 TPS |
| TPC-B | 2,898 TPS | 2,891 TPS | 2,877 TPS |

- **Pure read scenarios are unaffected** by consistency level — LSN checking overhead is negligible
- **Write-then-read (autocommit) is the only scenario with significant impact**: Each statement runs as a separate transaction; Session mode waits for replica LSN catch-up before routing the read (-20%), Global routes all reads to Writer (-31%)
- **Explicit transactions (TPC-B, mixed TX) are unaffected** — once a write upgrades the transaction to Writer, all subsequent reads stay on Writer regardless of consistency level (by design: same-connection guarantee within a transaction)

### Throughput Ceiling (single instance)

Tested on a 2-vCPU EC2 instance (t-series). Trident uses a multi-threaded tokio async runtime and scales across all available cores.

| Scenario | 2-vCPU Proxy | Direct (no proxy) | Bottleneck |
|----------|-------------|-------------------|------------|
| Read-only SELECT | **~25,000 TPS** | 100,000 TPS | Proxy CPU saturated |
| TPC-B mixed R/W | **~4,000 TPS** | 6,200 TPS | Proxy + DB locks |

- Throughput scales linearly with CPU cores: ~12,500 read TPS per vCPU
- A 4-vCPU instance is expected to reach ~50K read TPS; 8-vCPU ~100K TPS
- For higher throughput, deploy multiple Trident instances behind a NLB (see Deployment section)

## Deployment

Three deployment options are provided:

| Method | Use Case | Reference |
|--------|----------|-----------|
| Systemd | Bare metal / VM | `deploy/systemd/` |
| Docker Compose | Local dev / smoke testing | `docker-compose.yml` |
| Kubernetes | Production clusters | `deploy/k8s/` |

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

## Hint Routing

Add a `/*+ ... */` comment at the beginning of your SQL to override the default routing decision. Requires `enable_hint_routing: true` in config.

### Route Hints

```sql
/*+ ROUTE_TO_WRITER */ SELECT now();           -- Force query to Writer
/*+ ROUTE_TO_READER */ SELECT now();           -- Force query to Reader
/*+ ROUTE_TO_ANALYTICS */ SELECT now();        -- Force query to Analytics node
```

### Per-Query Consistency Override

```sql
/*+ CONSISTENCY(eventual) */ SELECT * FROM orders WHERE id = 1;
/*+ CONSISTENCY(session) */ SELECT * FROM orders WHERE id = 1;
/*+ CONSISTENCY(global) */ SELECT * FROM orders WHERE id = 1;
```

**Format**: `/*+` (with plus sign), followed by the directive, followed by `*/`. The hint must appear before the SQL statement. Case-insensitive.

**Priority**: Hints > Custom Rules > Analytics Patterns > Cost-based routing > Default read/write classification.

## Admin Interface

Enable with `admin.enabled: true` (default listen: `127.0.0.1:9090`):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Embedded web management console |
| `/healthz` | GET | Health check (ready/live probe) |
| `/metrics` | GET | Prometheus-format metrics |
| `/reload` | POST | Hot reload routing configuration |
| `/client-stats` | GET | Per-IP client connection statistics |
| `/custom-rules` | GET/POST/DELETE | Dynamic custom routing rules |

**Security**: The admin interface has no authentication. Bind to a private address and restrict access via firewall/security groups.

## Hot Reload

The following routing parameters can be updated without restart:

```
enable_transaction_split, split_respects_consistency,
enable_hint_routing, enable_cost_routing, cost_threshold,
writer_readable, analytics_patterns, custom_rules, default_consistency
```

Trigger:
```bash
kill -SIGHUP <pid>
# or
curl -X POST http://127.0.0.1:9090/reload
```

## Documentation

- [DEPLOYMENT.md](DEPLOYMENT.md) — Deployment, configuration, and operations guide
- [DESIGN.md](DESIGN.md) — Architecture and design document
- [docs/architecture-en.html](docs/architecture-en.html) — Architecture diagram (English)
- [docs/architecture-cn.html](docs/architecture-cn.html) — Architecture diagram (Chinese)

## License

Private — All rights reserved.
