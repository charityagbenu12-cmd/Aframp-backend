use crate::treasury::handlers::{
    get_intervention, get_system_mode, list_interventions, trigger_intervention, EngineState,
};
use axum::{routing::get, routing::post, Router};

pub fn treasury_routes() -> Router<EngineState> {
    Router::new()
        .route("/intervention/trigger", post(trigger_intervention))
        .route("/intervention", get(list_interventions))
        .route("/intervention/:id", get(get_intervention))
        .route("/mode", get(get_system_mode))
}
