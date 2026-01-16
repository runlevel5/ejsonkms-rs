//! AWS KMS integration for encrypting and decrypting private keys.

use aws_sdk_kms::Client as KmsClient;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors that can occur during KMS operations.
#[derive(Error, Debug)]
pub enum KmsError {
    #[error("unable to decrypt private key: {0}")]
    Decrypt(String),
    #[error("unable to encrypt private key: {0}")]
    Encrypt(String),
    #[error("invalid encrypted data format: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

impl KmsError {
    /// Returns a sanitized error message safe for user display.
    ///
    /// Internal error details are hidden to prevent leaking sensitive information.
    #[must_use]
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::Decrypt(_) => {
                "Failed to decrypt private key. Check your AWS credentials and KMS key permissions."
            }
            Self::Encrypt(_) => {
                "Failed to encrypt private key. Check your AWS credentials and KMS key permissions."
            }
            Self::Base64Decode(_) => "Invalid encrypted data format.",
        }
    }

    /// Returns the internal error details (for logging only, not user display).
    #[allow(dead_code)]
    #[must_use]
    pub fn internal_details(&self) -> Option<&str> {
        match self {
            Self::Decrypt(s) | Self::Encrypt(s) => Some(s),
            Self::Base64Decode(_) => None,
        }
    }
}

/// Creates a new KMS client with optional custom endpoint.
///
/// # Security
///
/// The `FAKE_AWSKMS_URL` environment variable is only available in debug builds
/// to prevent endpoint redirection attacks in production.
pub async fn new_kms_client(aws_region: Option<&str>) -> KmsClient {
    #[cfg(debug_assertions)]
    let fake_kms_endpoint = std::env::var("FAKE_AWSKMS_URL").ok();
    #[cfg(not(debug_assertions))]
    let fake_kms_endpoint: Option<String> = None;

    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

    if let Some(region) = aws_region {
        config_loader = config_loader.region(aws_config::Region::new(region.to_string()));
    }

    let config = config_loader.load().await;
    let mut kms_config_builder = aws_sdk_kms::config::Builder::from(&config);

    if let Some(endpoint) = fake_kms_endpoint {
        kms_config_builder = kms_config_builder.endpoint_url(endpoint);
    }

    KmsClient::from_conf(kms_config_builder.build())
}

/// Decrypts a base64-encoded KMS ciphertext and returns the plaintext private key.
///
/// # Security
///
/// The returned [`Zeroizing<String>`] automatically zeroizes memory when dropped,
/// preventing sensitive data from lingering in memory.
pub async fn decrypt_private_key_with_kms(
    private_key_enc: &str,
    aws_region: Option<&str>,
) -> Result<Zeroizing<String>, KmsError> {
    let kms_client = new_kms_client(aws_region).await;
    let encrypted_value = BASE64.decode(private_key_enc)?;

    let response = kms_client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(encrypted_value))
        .send()
        .await
        .map_err(|e| KmsError::Decrypt(e.to_string()))?;

    let plaintext = response
        .plaintext()
        .ok_or_else(|| KmsError::Decrypt("no plaintext in response".to_owned()))?;

    String::from_utf8(plaintext.as_ref().to_vec())
        .map(Zeroizing::new)
        .map_err(|e| KmsError::Decrypt(format!("invalid UTF-8: {e}")))
}

/// Encrypts a private key using AWS KMS and returns the base64-encoded ciphertext.
pub async fn encrypt_private_key_with_kms(
    private_key: &str,
    kms_key_id: &str,
    aws_region: Option<&str>,
) -> Result<String, KmsError> {
    let kms_client = new_kms_client(aws_region).await;

    let response = kms_client
        .encrypt()
        .key_id(kms_key_id)
        .plaintext(aws_sdk_kms::primitives::Blob::new(private_key.as_bytes()))
        .send()
        .await
        .map_err(|e| KmsError::Encrypt(e.to_string()))?;

    let ciphertext = response
        .ciphertext_blob()
        .ok_or_else(|| KmsError::Encrypt("no ciphertext in response".to_owned()))?;

    Ok(BASE64.encode(ciphertext.as_ref()))
}
