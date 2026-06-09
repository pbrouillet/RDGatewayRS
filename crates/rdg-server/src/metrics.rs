//! Application-level metrics using OpenTelemetry.

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
use std::sync::OnceLock;

pub struct Metrics {
    pub connections_active: UpDownCounter<i64>,
    pub requests_total: Counter<u64>,
    pub relay_duration_seconds: Histogram<f64>,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub fn get() -> &'static Metrics {
    METRICS.get_or_init(|| {
        let meter = global::meter("rdg-gateway");

        Metrics {
            connections_active: meter
                .i64_up_down_counter("rdg.connections.active")
                .with_description("Number of active relay sessions")
                .build(),
            requests_total: meter
                .u64_counter("rdg.requests.total")
                .with_description("Total HTTP/WebSocket requests received")
                .build(),
            relay_duration_seconds: meter
                .f64_histogram("rdg.relay.duration_seconds")
                .with_description("Duration of relay sessions in seconds")
                .build(),
        }
    })
}
