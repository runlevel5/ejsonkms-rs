//! ejsonkms - Manage encrypted secrets using EJSON & AWS KMS
//!
//! This library combines EJSON (encrypted JSON) with AWS KMS for secure secret management.
//! The private key used for EJSON decryption is encrypted with KMS and stored in the EJSON
//! file itself, allowing secrets to be safely committed to version control.

pub mod kms;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

pub use kms::{decrypt_private_key_with_kms, encrypt_private_key_with_kms, KmsError};

#[derive(Error, Debug)]
pub enum EjsonKmsError {
    #[error("missing _private_key_enc field")]
    MissingPrivateKeyEnc,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("KMS error: {0}")]
    KmsError(#[from] KmsError),
    #[error("EJSON error: {0}")]
    EjsonError(String),
}

/// Keys used in an EjsonKms file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EjsonKmsKeys {
    #[serde(rename = "_public_key")]
    pub public_key: String,
    #[serde(rename = "_private_key_enc")]
    pub private_key_enc: String,
    #[serde(skip)]
    pub private_key: String,
}

/// Minimal structure for reading EJSON file to extract _private_key_enc
#[derive(Debug, Deserialize)]
struct EjsonKmsFile {
    #[serde(rename = "_private_key_enc")]
    private_key_enc: Option<String>,
}

/// Output structure for keygen (matches the Go version)
#[derive(Debug, Serialize)]
pub struct EjsonKmsOutput {
    #[serde(rename = "_public_key")]
    pub public_key: String,
    #[serde(rename = "_private_key_enc")]
    pub private_key_enc: String,
}

impl From<&EjsonKmsKeys> for EjsonKmsOutput {
    fn from(keys: &EjsonKmsKeys) -> Self {
        EjsonKmsOutput {
            public_key: keys.public_key.clone(),
            private_key_enc: keys.private_key_enc.clone(),
        }
    }
}

/// Generates a new EJSON keypair with the private key encrypted by KMS
pub async fn keygen(
    kms_key_id: &str,
    aws_region: Option<&str>,
) -> Result<EjsonKmsKeys, EjsonKmsError> {
    // Generate a new EJSON keypair
    let (public_key, private_key) =
        ejson::generate_keypair().map_err(|e| EjsonKmsError::EjsonError(e.to_string()))?;

    // Encrypt the private key with KMS
    let private_key_enc =
        encrypt_private_key_with_kms(&private_key, kms_key_id, aws_region).await?;

    Ok(EjsonKmsKeys {
        public_key,
        private_key_enc,
        private_key,
    })
}

/// Decrypts an EJSON file using KMS to first decrypt the private key
pub async fn decrypt<P: AsRef<Path>>(
    ejson_file_path: P,
    aws_region: Option<&str>,
) -> Result<Vec<u8>, EjsonKmsError> {
    let path = ejson_file_path.as_ref();

    // Find the encrypted private key in the file
    let private_key_enc = find_private_key_enc(path)?;

    // Decrypt the private key using KMS
    let kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    // Decrypt the EJSON file using the decrypted private key
    // Pass empty string for keydir since we're providing the private key directly
    let decrypted = ejson::decrypt_file(path, "", &kms_decrypted_private_key)
        .map_err(|e| EjsonKmsError::EjsonError(e.to_string()))?;

    Ok(decrypted)
}

/// Finds the _private_key_enc field in an EJSON file
pub fn find_private_key_enc<P: AsRef<Path>>(ejson_file_path: P) -> Result<String, EjsonKmsError> {
    let content = fs::read_to_string(ejson_file_path)?;
    let file: EjsonKmsFile = serde_json::from_str(&content)?;

    file.private_key_enc
        .filter(|s| !s.is_empty())
        .ok_or(EjsonKmsError::MissingPrivateKeyEnc)
}
