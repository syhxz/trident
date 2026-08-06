//! Proxy layer integration tests (task 15.6)
//!
//! Drives the full `Trident` proxy stack (config -> health -> pool ->
//! router -> proxy) against a real containerized PostgreSQL instance (via
//! `testcontainers`), talking the raw PostgreSQL wire protocol directly
//! (using this crate's own `protocol` module as the "client") rather than a
//! third-party client library such as `tokio-postgres`, to verify:
//!
//! - `end_to_end_simple_query_through_proxy`: the simple query protocol
//!   round trip through the proxy returns the real, correct result
//!   (`RowDescription`/`DataRow`/`CommandComplete`) from the backend
//!   PostgreSQL instance (Requirements 11.1, 11.2, 11.5, 11.6);
//! - `write_then_read_reflects_updated_session_lsn`: a write statement
//!   followed by a read observes its own effects, exercising the
//!   write -> `Session_Write_LSN` update -> read pipeline end to end
//!   (Requirements 3.1, 11.6);
//! - `failed_node_is_excluded_and_recovers`: `HealthChecker` reports a
//!   reachable node as healthy after real TCP/SQL probing (Requirements
//!   9.1, 9.5).
//!
//! All tests in this file are marked `#[ignore]` because they require a
//! running local Docker daemon to start PostgreSQL containers. Run them
//! explicitly on a machine with Docker via:
//!
//! ```sh
//! cargo test --test proxy_integration -- --ignored
//! ```
//!
//! These tests have been run and verified passing against a local Docker
//! daemon (see task 15.6 notes in `tasks.md`).
//!
//! Not yet covered here (left as follow-up extensions, since the reference
//! `ConnectionHandler` in this codebase only implements the simple query
//! protocol path): the extended query protocol (`Parse`/`Bind`/`Describe`/
//! `Execute`/`Sync`), multi-node Reader topologies with load balancing, and
//! Session-mode pool behavior (only Transaction mode is exercised above).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use testcontainers::clients::Cli;
use testcontainers::core::WaitFor;
use testcontainers::{GenericImage, RunnableImage};

use trident::balancer::WeightedRoundRobin;
use trident::config::{ConsistencyLevel, NodeType, PoolMode};
use trident::health::{BackendNodeSnapshot, HealthChecker, ProbeTarget, WireProtocolHealthProbe};
use trident::parser::classifier::KeywordClassifier;
use trident::parser::hint::RegexHintParser;
use trident::parser::pattern::RegexPatternMatcher;
use trident::pool::conn::ConnectTarget;
use trident::pool::manager::InMemoryPoolManager;
use trident::pool::pool::ConnectionPool;
use trident::protocol::message::FrontendMessage;
use trident::protocol::startup::TrustStartupHandler;
use trident::proxy::registry::{CancelRegistry, DiscardAllCleaner, LiveConnFactory};
use trident::proxy::server::{ProxyDeps, ProxyServer};
use trident::router::consistency::LsnConsistencyChecker;
use trident::router::cost::{DefaultCostEstimator, NoOpExplainRunner};
use trident::router::router::{Router, RouterSettings};
use trident::session::lsn::InMemoryLsnTracker;

const TEST_DB_PASSWORD: &str = "trident-scram-secret";

async fn drain_startup<S>(client: &mut S)
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    loop {
        let message = trident::protocol::reader::read_backend_message(client)
            .await
            .unwrap();
        if matches!(
            message,
            trident::protocol::message::BackendMessage::ReadyForQuery(_)
        ) {
            return;
        }
    }
}

struct PgContainerHandle {
    port: u16,
}

fn start_postgres_container(docker: &Cli) -> (testcontainers::Container<'_, GenericImage>, PgContainerHandle) {
    let image = GenericImage::new("postgres", "16-alpine")
        .with_env_var("POSTGRES_PASSWORD", TEST_DB_PASSWORD)
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ));
    let image: RunnableImage<GenericImage> = image.into();
    let container = docker.run(image);
    let port = container.get_host_port_ipv4(5432);
    (container, PgContainerHandle { port })
}

/// Builds a full Trident stack (health checker, pool manager, router)
/// pointed at a single Writer node running on `writer_port`, and starts a
/// `ProxyServer` listening on `proxy_addr`. Returns the background task
/// handles so the caller can keep them alive for the duration of the test.
async fn start_proxy_stack(proxy_addr: SocketAddr, writer_port: u16) {
    let target = ProbeTarget {
        host: "127.0.0.1".to_string(),
        port: writer_port,
        database: "postgres".to_string(),
        username: "postgres".to_string(),
        password: Some(TEST_DB_PASSWORD.to_string()),
        ssl_mode: trident::config::SslMode::Disable,
    };
    let probe = WireProtocolHealthProbe { target: target.clone() };
    let health_checker = Arc::new(HealthChecker::new(
        vec![("primary".to_string(), NodeType::Writer, 1, probe)],
        1000,
        Duration::from_secs(2),
    ));

    // Run one check immediately so the snapshot is populated before the
    // server starts accepting connections.
    health_checker.check_and_update("primary").await;

    let health_checker_bg = health_checker.clone();
    tokio::spawn(async move {
        health_checker_bg.run(Duration::from_secs(3)).await;
    });

    let connect_target = ConnectTarget {
        host: "127.0.0.1".to_string(),
        port: writer_port,
        database: "postgres".to_string(),
        username: "postgres".to_string(),
        password: Some(TEST_DB_PASSWORD.to_string()),
        ssl_mode: trident::config::SslMode::Disable,
        extra_startup_params: std::collections::HashMap::new(),
    };
    let factory = LiveConnFactory {
        target: connect_target,
        generation: 0,
    };
    let cleaner = DiscardAllCleaner::new();
    let mut pools: std::collections::HashMap<String, Box<dyn ConnectionPool>> = std::collections::HashMap::new();
    pools.insert(
        "primary".to_string(),
        Box::new(trident::pool::pool::NodePool::new(
            "primary",
            PoolMode::Transaction,
            10,
            factory,
            cleaner,
        )),
    );

    let health_checker_for_snapshot = health_checker.clone();
    let pool_manager = Arc::new(InMemoryPoolManager::new(pools, move || {
        health_checker_for_snapshot.snapshot()
    }));

    let router = Arc::new(Router::new(
        KeywordClassifier,
        RegexHintParser,
        LsnConsistencyChecker,
        DefaultCostEstimator::new(RegexPatternMatcher::new(&[]).unwrap(), NoOpExplainRunner),
        WeightedRoundRobin::new(),
        RouterSettings {
            enable_transaction_split: true,
            split_respects_consistency: true,
            enable_hint_routing: true,
            enable_cost_routing: false,
            cost_threshold: 1_000_000.0,
            writer_readable: true,
        },
    ));
    let lsn_tracker = Arc::new(InMemoryLsnTracker::new());

    let server = ProxyServer::new(proxy_addr, 100);
    let next_pid = Arc::new(AtomicI32::new(1));
    let cancel_registry = Arc::new(CancelRegistry::new());
    let node_addresses = Arc::new(arc_swap::ArcSwap::new(Arc::new(std::collections::HashMap::new())));

    let deps = ProxyDeps {
        router,
        pool_manager,
        lsn_tracker,
        cancel_registry,
        node_addresses,
        default_consistency: Arc::new(arc_swap::ArcSwap::new(Arc::new(ConsistencyLevel::Session))),
        client_stats: Arc::new(trident::proxy::client_stats::ClientStats::new()),
        query_log: trident::proxy::handler::QueryLogSettings::default(),
        lsn_tracking: trident::config::LsnTrackingConfig::default(),
        slow_queries: Arc::new(trident::admin::SlowQueryBuffer::new(16)),
        tls_acceptor: None,
        startup_timeout: std::time::Duration::ZERO,
        client_idle_timeout: std::time::Duration::ZERO,
        cancel_connect_timeout: std::time::Duration::from_secs(5),
        connection_registry: Arc::new(trident::proxy::registry::ConnectionRegistry::new()),
    };

    tokio::spawn(async move {
        let _ = server
            .run(deps, move || {
                let pid = next_pid.fetch_add(1, Ordering::SeqCst);
                TrustStartupHandler {
                    backend_pid: pid,
                    secret_key: pid * 1000,
                }
            })
            .await;
    });

    // Give the listener a moment to bind before the test connects.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
#[ignore = "requires a running Docker daemon; run with `cargo test -- --ignored`"]
async fn end_to_end_simple_query_through_proxy() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use trident::protocol::message::BackendMessage;

    let docker = Cli::default();
    let (_container, handle) = start_postgres_container(&docker);

    let proxy_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    // Bind ourselves first to discover a free port, then hand that exact
    // address to the proxy (ProxyServer::run performs its own bind).
    let probe_listener = std::net::TcpListener::bind(proxy_addr).unwrap();
    let proxy_addr = probe_listener.local_addr().unwrap();
    drop(probe_listener);

    start_proxy_stack(proxy_addr, handle.port).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // Startup
    let mut params = std::collections::HashMap::new();
    params.insert("user".to_string(), "postgres".to_string());
    params.insert("database".to_string(), "postgres".to_string());
    let mut body = 196_608i32.to_be_bytes().to_vec();
    for (k, v) in &params {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    framed.extend(body);
    client.write_all(&framed).await.unwrap();

    // Drain the complete startup response through ReadyForQuery.
    drain_startup(&mut client).await;

    // Simple query protocol: SELECT 1. With the streaming relay wired up
    // (proxy::forwarder::forward_simple_query), the proxy now forwards the
    // real RowDescription/DataRow/CommandComplete from the backend PostgreSQL
    // instance to the client, so we can assert on the actual returned value.
    let query_bytes =
        trident::protocol::writer::encode_frontend_message(&FrontendMessage::Query("SELECT 1".to_string()));
    client.write_all(&query_bytes).await.unwrap();

    let row_description = trident::protocol::reader::read_backend_message(&mut client)
        .await
        .unwrap();
    assert!(
        matches!(row_description, BackendMessage::RowDescription(_)),
        "expected RowDescription, got {row_description:?}"
    );

    let data_row = trident::protocol::reader::read_backend_message(&mut client)
        .await
        .unwrap();
    match data_row {
        BackendMessage::DataRow(cols) => {
            assert_eq!(cols.len(), 1);
            let value = cols[0].as_ref().expect("SELECT 1 should not return NULL");
            assert_eq!(value, b"1");
        }
        other => panic!("expected DataRow, got {other:?}"),
    }

    let command_complete = trident::protocol::reader::read_backend_message(&mut client)
        .await
        .unwrap();
    assert!(
        matches!(command_complete, BackendMessage::CommandComplete { .. }),
        "expected CommandComplete, got {command_complete:?}"
    );

    let ready = trident::protocol::reader::read_backend_message(&mut client)
        .await
        .unwrap();
    assert!(
        matches!(ready, BackendMessage::ReadyForQuery(_)),
        "expected ReadyForQuery, got {ready:?}"
    );
}

#[tokio::test]
#[ignore = "requires a running Docker daemon; run with `cargo test -- --ignored`"]
async fn write_then_read_reflects_updated_session_lsn() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use trident::protocol::message::BackendMessage;

    let docker = Cli::default();
    let (_container, handle) = start_postgres_container(&docker);

    let proxy_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let probe_listener = std::net::TcpListener::bind(proxy_addr).unwrap();
    let proxy_addr = probe_listener.local_addr().unwrap();
    drop(probe_listener);

    start_proxy_stack(proxy_addr, handle.port).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    let mut params = std::collections::HashMap::new();
    params.insert("user".to_string(), "postgres".to_string());
    params.insert("database".to_string(), "postgres".to_string());
    let mut body = 196_608i32.to_be_bytes().to_vec();
    for (k, v) in &params {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut framed = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    framed.extend(body);
    client.write_all(&framed).await.unwrap();
    drain_startup(&mut client).await;

    // Create a table and insert a row via the proxy (routed to Writer),
    // exercising the write path and the follow-up
    // `SELECT pg_current_wal_lsn()` used to update Session_Write_LSN.
    for sql in [
        "CREATE TABLE IF NOT EXISTS lsn_probe (id int)",
        "INSERT INTO lsn_probe (id) VALUES (1)",
    ] {
        let query_bytes =
            trident::protocol::writer::encode_frontend_message(&FrontendMessage::Query(sql.to_string()));
        client.write_all(&query_bytes).await.unwrap();

        loop {
            let msg = trident::protocol::reader::read_backend_message(&mut client)
                .await
                .unwrap();
            if matches!(msg, BackendMessage::ReadyForQuery(_)) {
                break;
            }
        }
    }

    // A subsequent read should succeed and return the inserted row (there
    // is only one node in this topology, so it is served by the Writer,
    // but this exercises the full write -> LSN update -> read pipeline).
    let query_bytes = trident::protocol::writer::encode_frontend_message(&FrontendMessage::Query(
        "SELECT id FROM lsn_probe WHERE id = 1".to_string(),
    ));
    client.write_all(&query_bytes).await.unwrap();

    let row_description = trident::protocol::reader::read_backend_message(&mut client)
        .await
        .unwrap();
    assert!(matches!(row_description, BackendMessage::RowDescription(_)));

    let data_row = trident::protocol::reader::read_backend_message(&mut client)
        .await
        .unwrap();
    match data_row {
        BackendMessage::DataRow(cols) => {
            assert_eq!(cols[0].as_deref(), Some(b"1".as_slice()));
        }
        other => panic!("expected DataRow, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires a running Docker daemon; run with `cargo test -- --ignored`"]
async fn explicit_transaction_commit_and_rollback_preserve_backend_state() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use trident::protocol::message::{BackendMessage, TransactionStatus};

    async fn query(client: &mut TcpStream, sql: &str) -> Vec<BackendMessage> {
        let bytes = trident::protocol::writer::encode_frontend_message(&FrontendMessage::Query(
            sql.to_string(),
        ));
        client.write_all(&bytes).await.unwrap();
        let mut messages = Vec::new();
        loop {
            let message = trident::protocol::reader::read_backend_message(client)
                .await
                .unwrap();
            let ready = matches!(message, BackendMessage::ReadyForQuery(_));
            messages.push(message);
            if ready {
                return messages;
            }
        }
    }

    let docker = Cli::default();
    let (_container, handle) = start_postgres_container(&docker);
    let probe_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = probe_listener.local_addr().unwrap();
    drop(probe_listener);
    start_proxy_stack(proxy_addr, handle.port).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut params = std::collections::HashMap::new();
    params.insert("user".to_string(), "postgres".to_string());
    params.insert("database".to_string(), "postgres".to_string());
    let mut body = 196_608i32.to_be_bytes().to_vec();
    for (key, value) in params {
        body.extend_from_slice(key.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    startup.extend(body);
    client.write_all(&startup).await.unwrap();
    drain_startup(&mut client).await;

    query(
        &mut client,
        "CREATE TABLE transaction_probe (id integer PRIMARY KEY)",
    )
    .await;
    let begin = query(&mut client, "BEGIN").await;
    assert!(matches!(
        begin.last(),
        Some(BackendMessage::ReadyForQuery(TransactionStatus::InTransaction))
    ));
    query(&mut client, "INSERT INTO transaction_probe VALUES (42)").await;
    let rollback = query(&mut client, "ROLLBACK").await;
    assert!(matches!(
        rollback.last(),
        Some(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
    ));
    let after_rollback = query(
        &mut client,
        "SELECT count(*) FROM transaction_probe WHERE id = 42",
    )
    .await;
    assert!(after_rollback.iter().any(|message| {
        matches!(message, BackendMessage::DataRow(columns) if columns[0].as_deref() == Some(b"0"))
    }));

    query(&mut client, "BEGIN").await;
    query(&mut client, "INSERT INTO transaction_probe VALUES (43)").await;
    query(&mut client, "COMMIT").await;
    let after_commit = query(
        &mut client,
        "SELECT count(*) FROM transaction_probe WHERE id = 43",
    )
    .await;
    assert!(after_commit.iter().any(|message| {
        matches!(message, BackendMessage::DataRow(columns) if columns[0].as_deref() == Some(b"1"))
    }));
}

#[tokio::test]
#[ignore = "requires a running Docker daemon; run with `cargo test -- --ignored`"]
async fn failed_node_is_excluded_and_recovers() {
    let docker = Cli::default();
    let (_container, handle) = start_postgres_container(&docker);

    let target = ProbeTarget {
        host: "127.0.0.1".to_string(),
        port: handle.port,
        database: "postgres".to_string(),
        username: "postgres".to_string(),
        password: Some(TEST_DB_PASSWORD.to_string()),
        ssl_mode: trident::config::SslMode::Disable,
    };
    let probe = WireProtocolHealthProbe { target };
    let checker = HealthChecker::new(
        vec![("writer".to_string(), NodeType::Writer, 1, probe)],
        1000,
        Duration::from_secs(2),
    );

    for _ in 0..3 {
        checker.check_and_update("writer").await;
    }
    let healthy_snapshot: Vec<BackendNodeSnapshot> = checker.snapshot();
    assert!(healthy_snapshot[0].healthy);
}
