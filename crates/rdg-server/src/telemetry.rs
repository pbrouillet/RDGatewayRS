//! OpenTelemetry initialization: traces, metrics, and logs exported via OTLP gRPC.

use anyhow::Result;
use opentelemetry::trace::TracerProvider;
use opentelemetry::{global, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use rdg_core::config::TelemetryConfig;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

static METER_PROVIDER: std::sync::OnceLock<SdkMeterProvider> = std::sync::OnceLock::new();
static TRACER_PROVIDER: std::sync::OnceLock<SdkTracerProvider> = std::sync::OnceLock::new();
static LOGGER_PROVIDER: std::sync::OnceLock<SdkLoggerProvider> = std::sync::OnceLock::new();

/// Probe the OTLP endpoint with a TCP connect and a short timeout.
/// Returns true if the endpoint is reachable.
async fn probe_endpoint(endpoint: &str) -> bool {
    let addr = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);

    match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

/// Initialize the tracing subscriber with optional OpenTelemetry export.
/// If `config.otlp_endpoint` is set and `config.enabled` is true, the endpoint is probed
/// first. If unreachable, a single warning is emitted and we fall back to console-only.
pub async fn init(config: &TelemetryConfig) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,rdg_server=debug,rdg_core=debug"));

    let fmt_layer = tracing_subscriber::fmt::layer();

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    if config.enabled {
        if let Some(endpoint) = &config.otlp_endpoint {
            // Probe connectivity before setting up exporters
            if !probe_endpoint(endpoint).await {
                registry.init();
                tracing::warn!(
                    "OTLP endpoint {} is unreachable — falling back to console-only logging",
                    endpoint
                );
                return Ok(());
            }

            let resource = Resource::builder()
                .with_attributes([
                    KeyValue::new("service.name", config.service_name.clone()),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_string()),
                ])
                .build();

            // Traces
            let trace_exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;

            let tracer_provider = SdkTracerProvider::builder()
                .with_resource(resource.clone())
                .with_batch_exporter(trace_exporter)
                .build();

            let tracer = tracer_provider.tracer("rdg-gateway");
            let _ = TRACER_PROVIDER.set(tracer_provider);

            let otel_trace_layer = OpenTelemetryLayer::new(tracer);

            // Logs
            let log_exporter = opentelemetry_otlp::LogExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;

            let logger_provider = SdkLoggerProvider::builder()
                .with_resource(resource.clone())
                .with_batch_exporter(log_exporter)
                .build();

            let otel_log_layer = OpenTelemetryTracingBridge::new(&logger_provider);
            let _ = LOGGER_PROVIDER.set(logger_provider);

            // Metrics
            let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;

            let meter_provider = SdkMeterProvider::builder()
                .with_resource(resource)
                .with_periodic_exporter(metric_exporter)
                .build();

            global::set_meter_provider(meter_provider.clone());
            let _ = METER_PROVIDER.set(meter_provider);

            registry
                .with(otel_trace_layer)
                .with(otel_log_layer)
                .init();

            tracing::info!("OpenTelemetry enabled (traces + logs + metrics), exporting to {}", endpoint);
            return Ok(());
        }
    }

    // Fallback: console-only
    registry.init();
    Ok(())
}

/// Gracefully flush and shut down OpenTelemetry providers.
pub fn shutdown() {
    if let Some(tracer) = TRACER_PROVIDER.get() {
        let _ = tracer.shutdown();
    }
    if let Some(logger) = LOGGER_PROVIDER.get() {
        let _ = logger.shutdown();
    }
    if let Some(meter) = METER_PROVIDER.get() {
        let _ = meter.shutdown();
    }
}
