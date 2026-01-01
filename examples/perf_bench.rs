//! Performance Benchmarking Example
//!
//! This example demonstrates memory and CPU profiling of the RADIUS server.
//! Use this with profiling tools like:
//! - `cargo flamegraph --example perf_bench` - CPU profiling
//! - `heaptrack ./target/release/examples/perf_bench` - Memory profiling
//! - `valgrind --tool=massif ./target/release/examples/perf_bench` - Memory usage
//!
//! Build with:
//! ```bash
//! cargo build --release --example perf_bench
//! ```

use radius_proto::auth::{encrypt_user_password, generate_request_authenticator};
use radius_proto::{Attribute, AttributeType, Code, Packet};
use radius_server::{RadiusServer, ServerConfig, SimpleAuthHandler};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

static REQUESTS_SENT: AtomicU64 = AtomicU64::new(0);
static RESPONSES_RECEIVED: AtomicU64 = AtomicU64::new(0);

/// Create PAP Access-Request
fn create_pap_request(username: &str, password: &str, secret: &[u8], id: u8) -> Packet {
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, id, req_auth);

    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, username)
            .expect("Failed to create User-Name"),
    );

    let encrypted_pwd = encrypt_user_password(password, secret, &req_auth);
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)
            .expect("Failed to create User-Password"),
    );

    packet.add_attribute(
        Attribute::new(AttributeType::NasIpAddress as u8, vec![127, 0, 0, 1])
            .expect("Failed to create NAS-IP-Address"),
    );

    packet
}

/// Send request and receive response
async fn send_and_receive(
    packet: Packet,
    server_addr: SocketAddr,
) -> Result<Packet, Box<dyn std::error::Error + Send + Sync>> {
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let packet_bytes = packet.encode()?;

    client_socket.send_to(&packet_bytes, server_addr).await?;
    REQUESTS_SENT.fetch_add(1, Ordering::Relaxed);

    let mut response_buf = vec![0u8; 4096];
    let timeout = tokio::time::timeout(
        Duration::from_secs(5),
        client_socket.recv_from(&mut response_buf),
    )
    .await??;

    let (len, _) = timeout;
    let response = Packet::decode(&response_buf[..len])?;
    RESPONSES_RECEIVED.fetch_add(1, Ordering::Relaxed);

    Ok(response)
}

/// Benchmark worker
async fn benchmark_worker(
    server_addr: SocketAddr,
    user_id: usize,
    num_requests: usize,
) -> Result<Duration, Box<dyn std::error::Error + Send + Sync>> {
    let secret = b"testing123";
    let username = format!("user{}", user_id);
    let password = "testpass";

    let start = Instant::now();

    for i in 0..num_requests {
        let id = (i % 256) as u8;
        let request = create_pap_request(&username, password, secret, id);
        let _response = send_and_receive(request, server_addr).await?;
    }

    Ok(start.elapsed())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("RADIUS Server Performance Benchmark");
    println!("===================================\n");

    // Create auth handler with test users
    let mut auth_handler = SimpleAuthHandler::new();
    for i in 0..100 {
        auth_handler.add_user(&format!("user{}", i), "testpass");
    }

    // Create minimal config
    let config = ServerConfig::new(
        "127.0.0.1:0".parse()?,
        b"testing123",
        Arc::new(auth_handler),
    );

    // Start server
    let server = RadiusServer::new(config).await?;
    let server_addr = server.local_addr()?;
    println!("Server started on {}", server_addr);

    // Spawn server task
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Benchmark parameters
    let num_workers = 10;
    let requests_per_worker = 1000;
    let total_requests = num_workers * requests_per_worker;

    println!("Benchmark configuration:");
    println!("  Workers: {}", num_workers);
    println!("  Requests per worker: {}", requests_per_worker);
    println!("  Total requests: {}\n", total_requests);

    // Run benchmark
    println!("Starting benchmark...");
    let bench_start = Instant::now();

    let mut tasks = Vec::new();
    for worker_id in 0..num_workers {
        let task = tokio::spawn(async move {
            benchmark_worker(server_addr, worker_id, requests_per_worker).await
        });
        tasks.push(task);
    }

    // Wait for all workers
    let mut total_worker_time = Duration::ZERO;
    for task in tasks {
        match task.await {
            Ok(Ok(duration)) => total_worker_time += duration,
            Ok(Err(e)) => eprintln!("Worker error: {}", e),
            Err(e) => eprintln!("Task error: {}", e),
        }
    }

    let bench_elapsed = bench_start.elapsed();

    // Print results
    println!("\nBenchmark Results:");
    println!("==================");
    println!("Total elapsed time: {:.2?}", bench_elapsed);
    println!("Requests sent: {}", REQUESTS_SENT.load(Ordering::Relaxed));
    println!(
        "Responses received: {}",
        RESPONSES_RECEIVED.load(Ordering::Relaxed)
    );

    let rps = total_requests as f64 / bench_elapsed.as_secs_f64();
    println!("\nThroughput: {:.0} requests/second", rps);

    let avg_latency_ms = bench_elapsed.as_millis() as f64 / total_requests as f64;
    println!("Average latency: {:.2} ms", avg_latency_ms);

    let concurrent_latency_ms = total_worker_time.as_millis() as f64 / total_requests as f64;
    println!("Per-worker average: {:.2} ms", concurrent_latency_ms);

    // Memory usage statistics would require platform-specific code
    // On Linux, you can use /proc/self/status
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmSize:") {
                    println!("{}", line);
                }
            }
        }
    }

    Ok(())
}
