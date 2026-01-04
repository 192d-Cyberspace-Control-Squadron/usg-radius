//! Prometheus metrics exporter for HA deployments
//!
//! Provides HTTP endpoint for Prometheus metrics scraping.
//! Exports metrics about backend health, cache statistics, rate limiting,
//! and session management.

#[cfg(feature = "ha")]
use crate::state::SharedSessionManager;
#[cfg(feature = "ha")]
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
#[cfg(feature = "ha")]
use std::sync::Arc;
#[cfg(feature = "ha")]
use std::time::SystemTime;
#[cfg(feature = "ha")]
use tower_http::trace::TraceLayer;

/// Prometheus metrics in text format
#[cfg(feature = "ha")]
#[derive(Debug, Clone)]
pub struct PrometheusMetrics {
    /// Metrics content in Prometheus text format
    pub content: String,
}

#[cfg(feature = "ha")]
impl PrometheusMetrics {
    /// Create new Prometheus metrics
    pub fn new() -> Self {
        Self {
            content: String::new(),
        }
    }

    /// Add a metric line
    fn add_metric(&mut self, name: &str, value: impl std::fmt::Display, help: &str) {
        self.content
            .push_str(&format!("# HELP {} {}\n", name, help));
        self.content.push_str(&format!("# TYPE {} gauge\n", name));
        self.content.push_str(&format!("{} {}\n", name, value));
    }

    /// Add a counter metric
    fn add_counter(&mut self, name: &str, value: impl std::fmt::Display, help: &str) {
        self.content
            .push_str(&format!("# HELP {} {}\n", name, help));
        self.content.push_str(&format!("# TYPE {} counter\n", name));
        self.content.push_str(&format!("{} {}\n", name, value));
    }

    /// Add a metric with labels
    fn add_metric_with_labels(
        &mut self,
        name: &str,
        labels: &[(&str, &str)],
        value: impl std::fmt::Display,
        help: &str,
    ) {
        self.content
            .push_str(&format!("# HELP {} {}\n", name, help));
        self.content.push_str(&format!("# TYPE {} gauge\n", name));

        let label_str = labels
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, v))
            .collect::<Vec<_>>()
            .join(",");

        self.content
            .push_str(&format!("{}{{{}}} {}\n", name, label_str, value));
    }
}

#[cfg(feature = "ha")]
impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics server state
#[cfg(feature = "ha")]
#[derive(Clone)]
pub struct MetricsState {
    session_manager: Arc<SharedSessionManager>,
    rate_limiter: Option<Arc<crate::ratelimit_ha::SharedRateLimiter>>,
    request_cache: Option<Arc<crate::cache_ha::SharedRequestCache>>,
    start_time: SystemTime,
}

#[cfg(feature = "ha")]
impl MetricsState {
    /// Create new metrics state
    pub fn new(session_manager: Arc<SharedSessionManager>) -> Self {
        Self {
            session_manager,
            rate_limiter: None,
            request_cache: None,
            start_time: SystemTime::now(),
        }
    }

    /// Create new metrics state with rate limiter
    pub fn with_rate_limiter(
        mut self,
        rate_limiter: Arc<crate::ratelimit_ha::SharedRateLimiter>,
    ) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Create new metrics state with request cache
    pub fn with_request_cache(
        mut self,
        request_cache: Arc<crate::cache_ha::SharedRequestCache>,
    ) -> Self {
        self.request_cache = Some(request_cache);
        self
    }

    /// Collect all metrics
    async fn collect_metrics(&self) -> PrometheusMetrics {
        let mut metrics = PrometheusMetrics::new();

        // Backend health metrics
        self.collect_backend_metrics(&mut metrics).await;

        // Cache metrics
        self.collect_cache_metrics(&mut metrics);

        // Rate limiter metrics
        self.collect_rate_limiter_metrics(&mut metrics).await;

        // Uptime metric
        self.collect_uptime_metrics(&mut metrics);

        metrics
    }

    /// Collect backend health metrics
    async fn collect_backend_metrics(&self, metrics: &mut PrometheusMetrics) {
        let backend_up = match self.session_manager.health_check().await {
            Ok(_) => 1,
            Err(_) => 0,
        };

        metrics.add_metric_with_labels(
            "radius_backend_up",
            &[("backend", "valkey")],
            backend_up,
            "Backend connectivity status (1 = up, 0 = down)",
        );
    }

    /// Collect cache statistics metrics
    fn collect_cache_metrics(&self, metrics: &mut PrometheusMetrics) {
        let cache_stats = self.session_manager.cache_stats();

        metrics.add_metric(
            "radius_cache_entries",
            cache_stats.entries,
            "Number of entries in local cache",
        );
    }

    /// Collect rate limiter metrics
    async fn collect_rate_limiter_metrics(&self, metrics: &mut PrometheusMetrics) {
        if let Some(ref rate_limiter) = self.rate_limiter {
            let stats = rate_limiter.get_stats();

            // Rate limit configuration
            metrics.add_metric(
                "radius_ratelimit_per_client_limit",
                stats.per_client_limit,
                "Per-client rate limit (requests per window)",
            );

            metrics.add_metric(
                "radius_ratelimit_global_limit",
                stats.global_limit,
                "Global rate limit (requests per window)",
            );

            metrics.add_metric(
                "radius_ratelimit_window_duration_seconds",
                stats.window_duration_secs,
                "Rate limit window duration in seconds",
            );

            // Current window counts
            if let Ok(global_count) = rate_limiter.get_global_count().await {
                metrics.add_metric(
                    "radius_ratelimit_current_global_count",
                    global_count,
                    "Current global request count in active window",
                );
            }
        }
    }

    /// Collect uptime metrics
    fn collect_uptime_metrics(&self, metrics: &mut PrometheusMetrics) {
        let uptime = self.start_time.elapsed().unwrap_or_default().as_secs();

        metrics.add_counter("radius_uptime_seconds", uptime, "Server uptime in seconds");
    }
}

/// Metrics endpoint handler
#[cfg(feature = "ha")]
async fn metrics_handler(State(state): State<MetricsState>) -> Response {
    let metrics = state.collect_metrics().await;

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        metrics.content,
    )
        .into_response()
}

/// Create metrics HTTP server
#[cfg(feature = "ha")]
pub fn create_metrics_server(session_manager: Arc<SharedSessionManager>) -> Router {
    let state = MetricsState::new(session_manager);

    Router::new()
        .route("/metrics", get(metrics_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Start metrics HTTP server on the specified address
#[cfg(feature = "ha")]
pub async fn start_metrics_server(
    session_manager: Arc<SharedSessionManager>,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = create_metrics_server(session_manager);

    tracing::info!("Starting metrics server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(all(test, feature = "ha"))]
mod tests {
    use super::*;
    use crate::state::MemoryStateBackend;

    #[test]
    fn test_prometheus_metrics_creation() {
        let metrics = PrometheusMetrics::new();
        assert_eq!(metrics.content, "");
    }

    #[test]
    fn test_add_metric() {
        let mut metrics = PrometheusMetrics::new();
        metrics.add_metric("test_metric", 42, "A test metric");

        assert!(metrics.content.contains("# HELP test_metric A test metric"));
        assert!(metrics.content.contains("# TYPE test_metric gauge"));
        assert!(metrics.content.contains("test_metric 42"));
    }

    #[test]
    fn test_add_counter() {
        let mut metrics = PrometheusMetrics::new();
        metrics.add_counter("test_counter", 100, "A test counter");

        assert!(
            metrics
                .content
                .contains("# HELP test_counter A test counter")
        );
        assert!(metrics.content.contains("# TYPE test_counter counter"));
        assert!(metrics.content.contains("test_counter 100"));
    }

    #[test]
    fn test_add_metric_with_labels() {
        let mut metrics = PrometheusMetrics::new();
        metrics.add_metric_with_labels(
            "test_labeled",
            &[("label1", "value1"), ("label2", "value2")],
            99,
            "A labeled metric",
        );

        assert!(
            metrics
                .content
                .contains("# HELP test_labeled A labeled metric")
        );
        assert!(metrics.content.contains("# TYPE test_labeled gauge"));
        assert!(
            metrics
                .content
                .contains("test_labeled{label1=\"value1\",label2=\"value2\"} 99")
        );
    }

    #[tokio::test]
    async fn test_metrics_state_creation() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let state = MetricsState::new(session_manager);

        assert!(state.start_time <= SystemTime::now());
    }

    #[tokio::test]
    async fn test_collect_backend_metrics() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let state = MetricsState::new(session_manager);

        let mut metrics = PrometheusMetrics::new();
        state.collect_backend_metrics(&mut metrics).await;

        assert!(metrics.content.contains("radius_backend_up"));
        assert!(metrics.content.contains("backend=\"valkey\""));
        assert!(metrics.content.contains(" 1")); // MemoryStateBackend is always up
    }

    #[tokio::test]
    async fn test_collect_cache_metrics() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let state = MetricsState::new(session_manager);

        let mut metrics = PrometheusMetrics::new();
        state.collect_cache_metrics(&mut metrics);

        assert!(metrics.content.contains("radius_cache_entries"));
        assert!(metrics.content.contains(" 0")); // Empty cache initially
    }

    #[tokio::test]
    async fn test_collect_uptime_metrics() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let state = MetricsState::new(session_manager);

        let mut metrics = PrometheusMetrics::new();
        state.collect_uptime_metrics(&mut metrics);

        assert!(metrics.content.contains("radius_uptime_seconds"));
        // Uptime should be >= 0
        assert!(metrics.content.contains("radius_uptime_seconds"));
    }

    #[tokio::test]
    async fn test_collect_all_metrics() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let state = MetricsState::new(session_manager);

        let metrics = state.collect_metrics().await;

        // Should contain all metric types
        assert!(metrics.content.contains("radius_backend_up"));
        assert!(metrics.content.contains("radius_cache_entries"));
        assert!(metrics.content.contains("radius_uptime_seconds"));
    }

    #[tokio::test]
    async fn test_metrics_with_rate_limiter() {
        use crate::ratelimit_ha::{SharedRateLimitConfig, SharedRateLimiter};
        use std::time::Duration;

        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let rate_limiter_config = SharedRateLimitConfig {
            per_client_limit: 100,
            global_limit: 1000,
            window_duration: Duration::from_secs(60),
        };

        let rate_limiter = Arc::new(SharedRateLimiter::new(
            Arc::clone(&session_manager),
            rate_limiter_config,
        ));

        let state = MetricsState::new(session_manager).with_rate_limiter(rate_limiter);

        let metrics = state.collect_metrics().await;

        // Should contain rate limiter metrics
        assert!(
            metrics
                .content
                .contains("radius_ratelimit_per_client_limit")
        );
        assert!(metrics.content.contains("radius_ratelimit_global_limit"));
        assert!(
            metrics
                .content
                .contains("radius_ratelimit_window_duration_seconds")
        );
        assert!(
            metrics
                .content
                .contains("radius_ratelimit_current_global_count")
        );
    }
}
