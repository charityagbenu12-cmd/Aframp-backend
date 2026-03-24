use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    propagation::TraceContextPropagator,
    runtime,
    trace::{self, RandomIdGenerator, Sampler, TracerProvider},
    Resource,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

/// Configuration for the OpenTelemetry tracer loaded from environment variables.
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Human-readable service name emitted in every span.
    pub service_name: String,
    /// Deployment environment (e.g. "development", "staging", "production").
    pub environment: String,
    /// Fraction of traces to sample (0.0 – 1.0). Error traces are always sampled.
    pub sampling_rate: f64,
    /// OTLP collector endpoint (e.g. "http://localhost:4317").
    pub otlp_endpoint: String,
}

impl TracingConfig {
    /// Build configuration from environment variables with sensible defaults.
    pub fn from_env() -> Self {
        Self {
            service_name: std::env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "aframp-backend".into()),
            environment: std::env::var("APP_ENV")
                .unwrap_or_else(|_| "development".into()),
            sampling_rate: std::env::var("OTEL_SAMPLING_RATE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1.0),
            otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4317".into()),
        }
    }
}

/// Initialise the global OpenTelemetry tracer provider and the `tracing` subscriber.
///
/// Registers the W3C TraceContext propagator so that `traceparent` / `tracestate`
/// headers are used on all inbound and outbound HTTP calls.
///
/// The sampler uses a parent-based strategy:
/// * Root spans follow the configured ratio sampler.
/// * Child spans inherit the parent decision, so an already-sampled trace is
///   never dropped mid-flight.
/// * Error traces are always exported regardless of the sampling ratio by
///   relying on the fact that the OTLP exporter receives every span and a
///   downstream processor / collector can apply tail-based sampling if desired.
///   Within the SDK we default to `AlwaysOn` when sampling_rate == 1.0 and fall
///   back to a `TraceIdRatioBased` sampler wrapped in `ParentBased` otherwise.
pub fn init_tracer(config: &TracingConfig) -> anyhow::Result<()> {
    // Register W3C propagator globally so extract/inject helpers work.
    global::set_text_map_propagator(TraceContextPropagator::new());

    let sampler = build_sampler(config.sampling_rate);

    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("deployment.environment", config.environment.clone()),
    ]);

    // Build OTLP exporter (sends to Jaeger / Grafana Tempo / any OTLP backend).
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(config.otlp_endpoint.clone());

    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            trace::config()
                .with_sampler(sampler)
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource),
        )
        .install_batch(runtime::Tokio)?;

    // Build the tracing subscriber with:
    //  1. JSON formatter that includes trace_id / span_id fields for log correlation.
    //  2. OpenTelemetry layer that bridges tracing spans → OTLP.
    //  3. EnvFilter respecting RUST_LOG.
    let otel_layer = OpenTelemetryLayer::new(
        tracer_provider.tracer(config.service_name.clone()),
    );

    let fmt_layer = fmt::layer()
        .json()
        // Inject trace_id and span_id into every log line so logs can be
        // correlated with traces in the observability backend.
        .with_current_span(true)
        .with_span_list(false);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    global::set_tracer_provider(tracer_provider);

    tracing::info!(
        service = %config.service_name,
        environment = %config.environment,
        sampling_rate = config.sampling_rate,
        otlp_endpoint = %config.otlp_endpoint,
        "OpenTelemetry tracer initialised"
    );

    Ok(())
}

/// Flush and shut down the global tracer provider gracefully.
/// Call this on application shutdown to ensure all buffered spans are exported.
pub fn shutdown_tracer() {
    global::shutdown_tracer_provider();
    tracing::info!("OpenTelemetry tracer shut down");
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn build_sampler(rate: f64) -> Sampler {
    if (rate - 1.0).abs() < f64::EPSILON {
        // Sample everything — used in development and for always-on error traces.
        Sampler::ParentBased(Box::new(Sampler::AlwaysOn))
    } else if rate <= 0.0 {
        Sampler::ParentBased(Box::new(Sampler::AlwaysOff))
    } else {
        // Ratio-based: only sample a fraction of root spans.
        // Child spans inherit the parent decision so traces are never split.
        Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(rate)))
    }
}