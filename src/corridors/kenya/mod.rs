//! Nigeria → Kenya payment corridor bridge.
//!
//! Orchestrates the full cross-border flow:
//!   1. Compliance check (corridor active, CBK limits)
//!   2. NGN/KES FX pricing
//!   3. Corridor fee calculation
//!   4. Recipient validation (M-Pesa phone active)
//!   5. KES disbursement via M-Pesa B2C
//!   6. Compliance tagging of the transaction
//!   7. Automatic cNGN refund on disbursement failure

pub mod models;
pub mod service;
pub mod handlers;
pub mod routes;
pub mod webhook;
