use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use rsa::{
    pkcs8::{EncodePublicKey, LineEnding},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

use crate::common::EncryptedSubmitRequest;

struct AppState {
    priv_key: RsaPrivateKey,
    pub_key_pem: String,
}

pub async fn run() {
    tracing_subscriber::fmt::init();

    info!("Generating RSA keys... this may take a moment.");
    let mut rng = rand::thread_rng();
    let priv_key = match RsaPrivateKey::new(&mut rng, 2048) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to generate RSA key: {}", e);
            return;
        }
    };
    let pub_key = RsaPublicKey::from(&priv_key);
    let pub_key_pem = match pub_key.to_public_key_pem(LineEnding::LF) {
        Ok(pem) => pem,
        Err(e) => {
            error!("Failed to encode public key to PEM: {}", e);
            return;
        }
    };

    let state = Arc::new(AppState {
        priv_key,
        pub_key_pem,
    });

    let app = Router::new()
        .route("/pubkey", get(get_pubkey))
        .route("/submit", post(submit_form))
        .with_state(state)
        .layer(CorsLayer::permissive());

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:3000").await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to 127.0.0.1:3000: {}", e);
            return;
        }
    };

    info!("Backend listening on 127.0.0.1:3000");
    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {}", e);
    }
}

async fn get_pubkey(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (StatusCode::OK, state.pub_key_pem.clone())
}

async fn submit_form(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EncryptedSubmitRequest>,
) -> impl IntoResponse {
    let padding = Oaep::new::<Sha256>();
    match state.priv_key.decrypt(padding, &payload.encrypted_data) {
        Ok(decrypted_bytes) => {
            match String::from_utf8(decrypted_bytes) {
                Ok(json_str) => {
                    info!("Received and decrypted payload: {}", json_str);
                    (StatusCode::OK, "Successfully received and decrypted payload")
                }
                Err(_) => {
                    error!("Decrypted data is not valid UTF-8");
                    (StatusCode::BAD_REQUEST, "Invalid UTF-8 in payload")
                }
            }
        }
        Err(e) => {
            error!("Failed to decrypt payload: {}", e);
            (StatusCode::BAD_REQUEST, "Failed to decrypt payload")
        }
    }
}
