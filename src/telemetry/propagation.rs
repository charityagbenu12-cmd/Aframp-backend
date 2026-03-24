use opentelemetry::{
    global,
    propagation::{Extractor, Injector},
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Inbound extraction — HTTP request headers → current span context
// ---------------------------------------------------------------------------

/// Wraps an Axum `HeaderMap` for the OpenTelemetry `Extractor` trait.
pub struct HeaderExtractor<'a>(pub &'a axum::http::HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(|k| k.as_str())
            .collect()
    }
}

/// Extract the W3C `traceparent` / `tracestate` context from inbound HTTP headers
/// and return an OpenTelemetry `Context` that becomes the parent for the root span.
pub fn extract_context(headers: &axum::http::HeaderMap) -> opentelemetry::Context {
    let extractor = HeaderExtractor(headers);
    global::get_text_map_propagator(|propagator| propagator.extract(&extractor))
}

// ---------------------------------------------------------------------------
// Outbound injection — current span context → outgoing request headers
// ---------------------------------------------------------------------------

/// Wraps a mutable `reqwest::HeaderMap` for the OpenTelemetry `Injector` trait.
pub struct ReqwestHeaderInjector<'a>(pub &'a mut HeaderMap);

impl<'a> Injector for ReqwestHeaderInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_str(key),
            HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, val);
        }
    }
}

/// Inject the current span's W3C trace context into an outbound `reqwest` header
/// map so downstream services (payment providers, Stellar Horizon, rate APIs)
/// receive the `traceparent` header and can continue the distributed trace.
pub fn inject_context(headers: &mut HeaderMap) {
    let cx = opentelemetry::Context::current();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut ReqwestHeaderInjector(headers));
    });
}