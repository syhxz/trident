# Pool Architecture Refactoring: Socket Ownership Migration

## Status: Ready to implement (design validated, `BackendConnection` struct defined)

## Goal
Move `BackendStream` (socket) ownership from `ConnectionRegistry` into the pool's
idle queue, eliminating 2 mutex locks per query on the hot path.

## Current Architecture (per autocommit query)
```
pool.acquire() → PooledConnection (metadata only)     [1 lock: idle queue]
registry.take() → BackendStream                       [1 lock: global HashMap]
... forward query ...
registry.insert() → put socket back                   [1 lock: global HashMap]
pool.release() → put metadata back                    [1 lock: idle queue]
```
Total: 4 mutex operations per query (reduced to ~0 by delayed-release cache hit,
but still 4 on cache miss: first query, node switch, dirty connection)

## Target Architecture
```
pool.acquire() → BackendConnection (metadata + socket) [1 lock: idle queue]
... forward query ...
pool.release() → BackendConnection back                [1 lock: idle queue]
```
Total: 2 mutex operations per query on cache miss. Zero on cache hit (delayed release).

## Key Design Decisions

### 1. `BackendConnection` (already defined in `pool/conn.rs`)
```rust
pub struct BackendConnection {
    pub meta: PooledConnection,
    pub stream: BufReader<MaybeTlsStream>,
    pub generation: u64,
    pub current_application_name: Option<String>,
}
```

### 2. `ConnectionPool` trait changes
```rust
async fn acquire(&self, session_id: &str) -> Result<BackendConnection, PoolError>;
async fn release(&self, session_id: &str, conn: BackendConnection) -> Result<(), PoolError>;
fn pin(&self, session_id: &str, conn: &mut BackendConnection);
fn discard(&self, conn: BackendConnection) -> Result<(), PoolError>;
fn release_session(&self, session_id: &str) -> Vec<BackendConnection>;
```

### 3. `ConnFactory` changes
```rust
pub trait ConnFactory: Send + Sync {
    fn create(&self, node_id: &str)
        -> impl Future<Output = Result<BackendConnection, PoolError>> + Send;
}
```
`LiveConnFactory` no longer inserts into registry — just returns `BackendConnection`.

### 4. `ConnCleaner` changes
```rust
pub trait ConnCleaner: Send + Sync {
    fn clean(&self, conn: &mut BackendConnection)
        -> impl Future<Output = Result<(), PoolError>> + Send;
    fn validate(&self, conn: &mut BackendConnection)
        -> impl Future<Output = Result<(), PoolError>> + Send;
    fn discard(&self, conn: &BackendConnection) {}
}
```
`DiscardAllCleaner` directly writes to `conn.stream` instead of take/insert from registry.

### 5. `NodePool` changes
```rust
pub struct NodePool<F: ConnFactory, C: ConnCleaner> {
    idle: Mutex<VecDeque<BackendConnection>>,           // was: VecDeque<PooledConnection>
    session_bindings: Mutex<HashMap<String, BackendConnection>>,
    pinned_by_session: Mutex<HashMap<String, Vec<BackendConnection>>>,
    ...
}
```

### 6. Handler changes
- `HeldBackend` struct → replaced by `BackendConnection` directly
- Remove all `connection_registry.take()` / `connection_registry.insert()` on hot path
- `cached_idle_backend: Option<BackendConnection>` (already done conceptually)

### 7. `ConnectionRegistry` fate
- Remove socket storage entirely
- Keep only `CancelRegistry` functionality (session→backend_pid mapping for cancel)
- Or rename to `CancelRegistry` and drop the socket HashMap

### 8. `PoolManager` changes
- Remove `connection_registry` field
- Remove socket cleanup in eviction path (dropping `BackendConnection` closes socket)
- `known_pids()` still works (pool owns all connections, can enumerate PIDs)

## File Change Summary

| File | Scope | Risk |
|------|-------|------|
| `pool/conn.rs` | Add `BackendConnection` (done) | Low |
| `pool/pool.rs` | Change trait + NodePool impl | High (1317 lines) |
| `proxy/registry.rs` | Simplify ConnFactory/Cleaner, remove socket storage | Medium |
| `proxy/handler.rs` | Replace HeldBackend, remove registry hot path | High (many call sites) |
| `pool/manager.rs` | Remove registry dependency | Medium |
| `main.rs` | Adapt pool/registry setup | Medium |
| `proxy/server.rs` | Adapt deps struct | Low |
| Tests (in pool.rs, handler.rs) | Adapt mock ConnFactory/Cleaner | Medium |

## Implementation Strategy

1. Create a feature branch
2. Start from `pool/pool.rs`: change traits, adapt `NodePool` implementation
3. Fix `registry.rs`: simplify `LiveConnFactory`/`DiscardAllCleaner`
4. Fix `handler.rs`: replace `HeldBackend`, remove registry calls
5. Fix `manager.rs`, `main.rs`, `server.rs`
6. Fix all tests
7. Compile and run full test suite
8. Benchmark against current delayed-release baseline

## Expected Performance Gain (on top of delayed-release)
- Cache miss path: 4 locks → 2 locks (50% reduction in lock operations)
- Eliminates `HashMap<(String, i32)>` lookup + String clone per acquire/release
- Estimated additional 5-10% throughput improvement in high-concurrency readonly

## Compatibility Notes
- `PooledConnection` struct remains (embedded in `BackendConnection.meta`)
- External-facing behavior is unchanged
- `CancelRegistry` is unaffected (only needs node_id + backend_pid + secret_key)
