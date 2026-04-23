//! Prometheus metrics for Merchant Gateway

use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec,
    HistogramVec, Registry,
};

pub struct MerchantGatewayMetrics {
    pub payment_intents_created: CounterVec,
    pub payment_intents_paid: CounterVec,
    pub payment_intents_expired: CounterVec,
    pub payment_intents_cancelled: CounterVec,
    pub payment_confirmation_time: HistogramVec,
    pub webhook_deliveries: CounterVec,
    pub webhook_failures: CounterVec,
    pub active_payment_intents: GaugeVec,
}

impl MerchantGatewayMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let payment_intents_created = register_counter_vec!(
            prometheus::opts!(
                "merchant_gateway_payment_intents_created_total",
                "Total payment intents created"
            ),
            &["merchant_id"]
        )?;
        registry.register(Box::new(payment_intents_created.clone()))?;

        let payment_intents_paid = register_counter_vec!(
            prometheus::opts!(
                "merchant_gateway_payment_intents_paid_total",
                "Total payment intents paid"
            ),
            &["merchant_id"]
        )?;
        registry.register(Box::new(payment_intents_paid.clone()))?;

        let payment_intents_expired = register_counter_vec!(
            prometheus::opts!(
                "merchant_gateway_payment_intents_expired_total",
                "Total payment intents expired"
            ),
            &["merchant_id"]
        )?;
        registry.register(Box::new(payment_intents_expired.clone()))?;

        let payment_intents_cancelled = register_counter_vec!(
            prometheus::opts!(
                "merchant_gateway_payment_intents_cancelled_total",
                "Total payment intents cancelled"
            ),
            &["merchant_id"]
        )?;
        registry.register(Box::new(payment_intents_cancelled.clone()))?;

        let payment_confirmation_time = register_histogram_vec!(
            prometheus::histogram_opts!(
                "merchant_gateway_payment_confirmation_seconds",
                "Time from payment creation to blockchain confirmation",
                vec![1.0, 2.0, 3.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
            ),
            &["merchant_id"]
        )?;
        registry.register(Box::new(payment_confirmation_time.clone()))?;

        let webhook_deliveries = register_counter_vec!(
            prometheus::opts!(
                "merchant_gateway_webhook_deliveries_total",
                "Total webhook deliveries attempted"
            ),
            &["merchant_id", "event_type", "status"]
        )?;
        registry.register(Box::new(webhook_deliveries.clone()))?;

        let webhook_failures = register_counter_vec!(
            prometheus::opts!(
                "merchant_gateway_webhook_failures_total",
                "Total webhook delivery failures"
            ),
            &["merchant_id", "event_type"]
        )?;
        registry.register(Box::new(webhook_failures.clone()))?;

        let active_payment_intents = register_gauge_vec!(
            prometheus::opts!(
                "merchant_gateway_active_payment_intents",
                "Number of active (pending) payment intents"
            ),
            &["merchant_id"]
        )?;
        registry.register(Box::new(active_payment_intents.clone()))?;

        Ok(Self {
            payment_intents_created,
            payment_intents_paid,
            payment_intents_expired,
            payment_intents_cancelled,
            payment_confirmation_time,
            webhook_deliveries,
            webhook_failures,
            active_payment_intents,
        })
    }
}
