# SOP: Credential Revocation (Password Reset / User Disable)

## Background

Trident pools backend connections and reuses them across client requests.
When a database user's password is changed or the user is disabled in
PostgreSQL, **idle connections in the pool that were authenticated with the
old credentials remain usable** until they expire (`max_lifetime`, default
30 minutes) or are actively validated out.

This is a fundamental property of all connection poolers: once a TCP
connection is established and authenticated, the backend does not
re-validate credentials on every query. The only mitigation is to
proactively terminate or drain the affected connections.

## Scope

This SOP applies when:
- A database user's password is rotated (planned or emergency)
- A database user is disabled or dropped
- Credentials are suspected to be compromised

## Procedure

### Option A: Drain via Admin API (Recommended)

Call the Trident admin API to drain all pooled connections for the user:

```bash
curl -X POST http://<admin-host>:<admin-port>/api/drain-user \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"username": "<db_username>"}'
```

**Response:**
```json
{"status": "ok", "username": "app_user", "pools_drained": 3}
```

**Effect:**
- All per-user pools for that username enter drain mode
- Idle connections are immediately dropped
- In-flight queries on checked-out connections complete normally, then the
  connection is discarded (not returned to pool)
- New connections will authenticate with whatever credentials the next
  client presents

### Option B: PostgreSQL-side Termination

Terminate all backend connections for the user directly in PostgreSQL:

```sql
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = '<db_username>'
  AND pid != pg_backend_pid();
```

**Effect:**
- All backend connections (including those checked out by in-flight
  queries) are forcibly terminated
- Trident detects the broken connections during the next idle validation
  cycle or when a client query attempts to use them
- Clients with in-flight queries will receive a connection error and
  must retry

### Option C: Full Pool Restart

For the most aggressive approach (e.g. suspected credential compromise):

```bash
# 1. Change the password in PostgreSQL
ALTER USER app_user PASSWORD 'new_password';

# 2. Drain via admin API
curl -X POST http://<admin-host>:<admin-port>/api/drain-user \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"username": "app_user"}'

# 3. Verify no remaining connections
curl http://<admin-host>:<admin-port>/api/overview \
  -H "Authorization: Bearer <admin-token>"
```

## Timing Guarantees

| Method | Idle connections cleared | In-flight queries |
|--------|------------------------|-------------------|
| Admin API drain | Immediately | Complete then discard |
| pg_terminate_backend | Immediately | Forcibly killed |
| Wait for expiry | Up to `max_lifetime` (default 30m) | Unaffected |

## Recommendations

1. **Routine rotation**: Use Option A (drain API) — zero client impact for
   idle connections, graceful handling of in-flight queries.

2. **Emergency revocation**: Use Option C (change password + drain API).
   If sub-second revocation is required, add Option B
   (`pg_terminate_backend`) after step 1.

3. **Reduce exposure window**: Consider lowering `pool.max_lifetime` to 5–10
   minutes for security-sensitive deployments. This reduces the worst-case
   window if the SOP is not immediately executed.

4. **Monitoring**: After executing the SOP, verify via `/api/overview` or
   Prometheus metric `trident_pool_idle_validation_discarded_total` that
   pools have been refreshed.
