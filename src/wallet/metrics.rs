use prometheus::{Counter, CounterVec, Gauge, Opts, Registry};

pub struct WalletMetrics {
    pub wallet_registrations: Counter,
    pub ownership_proof_failures: Counter,
    pub auth_challenges_issued: Counter,
    pub auth_challenges_verified: Counter,
    pub stellar_sync_events: Counter,
    pub wallet_activations: Counter,
    pub recovery_initiations: CounterVec,
    pub recovery_successes: CounterVec,
    pub recovery_failures: Counter,
    pub guardian_approvals: Counter,
    pub backup_confirmations: Counter,
    pub statement_generations: CounterVec,
    pub history_sync_events: CounterVec,
    pub deduplication_events: Counter,
    pub reconciliation_flags: Counter,
    pub wallets_unconfirmed_backup: Gauge,
    pub active_social_recovery_requests: Gauge,
    pub portfolio_valuation_snapshots: Counter,
    pub balance_reconciliation_events: Counter,
    pub discrepancy_detections: Counter,
}

impl WalletMetrics {
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let wallet_registrations = Counter::with_opts(Opts::new(
            "wallet_registrations_total",
            "Total wallet registrations",
        ))?;
        let ownership_proof_failures = Counter::with_opts(Opts::new(
            "wallet_ownership_proof_failures_total",
            "Ownership proof verification failures",
        ))?;
        let auth_challenges_issued = Counter::with_opts(Opts::new(
            "wallet_auth_challenges_issued_total",
            "Auth challenges issued",
        ))?;
        let auth_challenges_verified = Counter::with_opts(Opts::new(
            "wallet_auth_challenges_verified_total",
            "Auth challenges verified",
        ))?;
        let stellar_sync_events = Counter::with_opts(Opts::new(
            "wallet_stellar_sync_events_total",
            "Stellar sync events",
        ))?;
        let wallet_activations = Counter::with_opts(Opts::new(
            "wallet_activations_total",
            "Wallet activations on Stellar",
        ))?;
        let recovery_initiations = CounterVec::new(
            Opts::new("wallet_recovery_initiations_total", "Recovery initiations by method"),
            &["method"],
        )?;
        let recovery_successes = CounterVec::new(
            Opts::new("wallet_recovery_successes_total", "Successful recoveries by method"),
            &["method"],
        )?;
        let recovery_failures = Counter::with_opts(Opts::new(
            "wallet_recovery_failures_total",
            "Failed recovery attempts",
        ))?;
        let guardian_approvals = Counter::with_opts(Opts::new(
            "wallet_guardian_approvals_total",
            "Guardian approvals for social recovery",
        ))?;
        let backup_confirmations = Counter::with_opts(Opts::new(
            "wallet_backup_confirmations_total",
            "Backup confirmations recorded",
        ))?;
        let statement_generations = CounterVec::new(
            Opts::new("wallet_statement_generations_total", "Statement generations by type"),
            &["statement_type"],
        )?;
        let history_sync_events = CounterVec::new(
            Opts::new("wallet_history_sync_events_total", "History sync events by source"),
            &["source"],
        )?;
        let deduplication_events = Counter::with_opts(Opts::new(
            "wallet_history_deduplication_events_total",
            "History deduplication events",
        ))?;
        let reconciliation_flags = Counter::with_opts(Opts::new(
            "wallet_reconciliation_flags_total",
            "Unreconciled Stellar transactions flagged",
        ))?;
        let wallets_unconfirmed_backup = Gauge::with_opts(Opts::new(
            "wallet_unconfirmed_backup_count",
            "Wallets with unconfirmed backup",
        ))?;
        let active_social_recovery_requests = Gauge::with_opts(Opts::new(
            "wallet_active_social_recovery_requests",
            "Active social recovery requests",
        ))?;
        let portfolio_valuation_snapshots = Counter::with_opts(Opts::new(
            "portfolio_valuation_snapshots_total",
            "Portfolio valuation snapshots generated",
        ))?;
        let balance_reconciliation_events = Counter::with_opts(Opts::new(
            "portfolio_balance_reconciliation_events_total",
            "Balance reconciliation events",
        ))?;
        let discrepancy_detections = Counter::with_opts(Opts::new(
            "portfolio_discrepancy_detections_total",
            "Balance discrepancy detections",
        ))?;

        registry.register(Box::new(wallet_registrations.clone()))?;
        registry.register(Box::new(ownership_proof_failures.clone()))?;
        registry.register(Box::new(auth_challenges_issued.clone()))?;
        registry.register(Box::new(auth_challenges_verified.clone()))?;
        registry.register(Box::new(stellar_sync_events.clone()))?;
        registry.register(Box::new(wallet_activations.clone()))?;
        registry.register(Box::new(recovery_initiations.clone()))?;
        registry.register(Box::new(recovery_successes.clone()))?;
        registry.register(Box::new(recovery_failures.clone()))?;
        registry.register(Box::new(guardian_approvals.clone()))?;
        registry.register(Box::new(backup_confirmations.clone()))?;
        registry.register(Box::new(statement_generations.clone()))?;
        registry.register(Box::new(history_sync_events.clone()))?;
        registry.register(Box::new(deduplication_events.clone()))?;
        registry.register(Box::new(reconciliation_flags.clone()))?;
        registry.register(Box::new(wallets_unconfirmed_backup.clone()))?;
        registry.register(Box::new(active_social_recovery_requests.clone()))?;
        registry.register(Box::new(portfolio_valuation_snapshots.clone()))?;
        registry.register(Box::new(balance_reconciliation_events.clone()))?;
        registry.register(Box::new(discrepancy_detections.clone()))?;

        Ok(Self {
            wallet_registrations,
            ownership_proof_failures,
            auth_challenges_issued,
            auth_challenges_verified,
            stellar_sync_events,
            wallet_activations,
            recovery_initiations,
            recovery_successes,
            recovery_failures,
            guardian_approvals,
            backup_confirmations,
            statement_generations,
            history_sync_events,
            deduplication_events,
            reconciliation_flags,
            wallets_unconfirmed_backup,
            active_social_recovery_requests,
            portfolio_valuation_snapshots,
            balance_reconciliation_events,
            discrepancy_detections,
        })
    }
}
