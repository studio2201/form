use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FormPayload {
    pub name: String,
    pub email: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSubmitRequest {
    /// The RSA encrypted payload (JSON serialized `FormPayload`).
    pub encrypted_data: Vec<u8>,
}
