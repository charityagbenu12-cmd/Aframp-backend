use crate::error::AppError;
use crate::pos::handlers::PosState;
use crate::pos::models::PaymentNotification;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

/// WebSocket handler for real-time payment notifications
/// Merchants connect to this endpoint to receive instant payment confirmations
#[instrument(skip(state, ws))]
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Path(payment_id): Path<Uuid>,
    State(state): State<PosState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_websocket(socket, payment_id, state))
}

/// Handle WebSocket connection lifecycle
async fn handle_websocket(socket: WebSocket, payment_id: Uuid, state: PosState) {
    info!(payment_id = %payment_id, "WebSocket connection established");

    let (mut sender, mut receiver) = socket.split();

    // Fetch payment intent to get memo
    let payment = match state.payment_intent_service.get_payment_intent(payment_id).await {
        Ok(p) => p,
        Err(e) => {
            error!(payment_id = %payment_id, error = %e, "Failed to fetch payment intent");
            let _ = sender
                .send(Message::Text(
                    serde_json::json!({
                        "error": "Payment not found"
                    })
                    .to_string(),
                ))
                .await;
            return;
        }
    };

    // Subscribe to payment notifications
    let mut notification_rx = match state.lobby_service
        .register_payment(payment_id, payment.memo.clone())
        .await
    {
        Ok(rx) => rx,
        Err(e) => {
            error!(payment_id = %payment_id, error = %e, "Failed to register for notifications");
            let _ = sender
                .send(Message::Text(
                    serde_json::json!({
                        "error": "Failed to register for notifications"
                    })
                    .to_string(),
                ))
                .await;
            return;
        }
    };

    // Send initial status
    let initial_status = serde_json::json!({
        "type": "status",
        "payment_id": payment.id,
        "order_id": payment.order_id,
        "status": format!("{:?}", payment.status).to_lowercase(),
        "amount_expected": payment.amount_cngn.to_string(),
    });

    if let Err(e) = sender.send(Message::Text(initial_status.to_string())).await {
        error!(payment_id = %payment_id, error = %e, "Failed to send initial status");
        return;
    }

    // Heartbeat interval
    let mut heartbeat = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Handle incoming messages from client
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        info!(payment_id = %payment_id, message = %text, "Received WebSocket message");
                        
                        // Handle ping/pong
                        if text == "ping" {
                            if let Err(e) = sender.send(Message::Text("pong".to_string())).await {
                                error!(payment_id = %payment_id, error = %e, "Failed to send pong");
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!(payment_id = %payment_id, "WebSocket connection closed by client");
                        break;
                    }
                    Some(Err(e)) => {
                        error!(payment_id = %payment_id, error = %e, "WebSocket error");
                        break;
                    }
                    None => {
                        info!(payment_id = %payment_id, "WebSocket stream ended");
                        break;
                    }
                    _ => {}
                }
            }

            // Handle payment notifications
            notification = notification_rx.recv() => {
                match notification {
                    Ok(notif) => {
                        info!(
                            payment_id = %payment_id,
                            status = ?notif.status,
                            "Sending payment notification"
                        );

                        let message = serde_json::json!({
                            "type": "notification",
                            "payment_id": notif.payment_id,
                            "order_id": notif.order_id,
                            "status": format!("{:?}", notif.status).to_lowercase(),
                            "amount_expected": notif.amount_expected.to_string(),
                            "amount_received": notif.amount_received.map(|a| a.to_string()),
                            "stellar_tx_hash": notif.stellar_tx_hash,
                            "timestamp": notif.timestamp.to_rfc3339(),
                        });

                        if let Err(e) = sender.send(Message::Text(message.to_string())).await {
                            error!(payment_id = %payment_id, error = %e, "Failed to send notification");
                            break;
                        }

                        // Close connection after confirmation
                        if matches!(
                            notif.status,
                            crate::pos::models::PosPaymentStatus::Confirmed |
                            crate::pos::models::PosPaymentStatus::Discrepancy |
                            crate::pos::models::PosPaymentStatus::Failed
                        ) {
                            info!(payment_id = %payment_id, "Payment finalized, closing WebSocket");
                            let _ = sender.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(payment_id = %payment_id, error = %e, "Notification channel error");
                    }
                }
            }

            // Send heartbeat
            _ = heartbeat.tick() => {
                if let Err(e) = sender.send(Message::Ping(vec![])).await {
                    error!(payment_id = %payment_id, error = %e, "Failed to send heartbeat");
                    break;
                }
            }
        }
    }

    // Cleanup: unregister from lobby service
    state.lobby_service.unregister_payment(&payment.memo).await;
    info!(payment_id = %payment_id, "WebSocket connection closed");
}
