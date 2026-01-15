//! KMS module for encrypting and decrypting private keys with AWS KMS

use aws_sdk_kms::Client as KmsClient;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KmsError {
    #[error("unable to decrypt parameter: {0}")]
    DecryptError(String),
    #[error("unable to encrypt parameter: {0}")]
    EncryptError(String),
    #[error("base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
}

/// Creates a new KMS client with optional custom endpoint (for testing)
pub async fn new_kms_client(aws_region: Option<&str>) -> KmsClient {
    let fake_kms_endpoint = std::env::var("FAKE_AWSKMS_URL").ok();

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

/// Decrypts a base64-encoded KMS ciphertext and returns the plaintext private key
pub async fn decrypt_private_key_with_kms(
    private_key_enc: &str,
    aws_region: Option<&str>,
) -> Result<String, KmsError> {
    let kms_client = new_kms_client(aws_region).await;

    let encrypted_value = BASE64.decode(private_key_enc)?;

    let response = kms_client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(encrypted_value))
        .send()
        .await
        .map_err(|e| KmsError::DecryptError(e.to_string()))?;

    let plaintext = response
        .plaintext()
        .ok_or_else(|| KmsError::DecryptError("no plaintext in response".to_string()))?;

    String::from_utf8(plaintext.as_ref().to_vec())
        .map_err(|e| KmsError::DecryptError(format!("invalid UTF-8: {}", e)))
}

/// Encrypts a private key using AWS KMS and returns the base64-encoded ciphertext
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
        .map_err(|e| KmsError::EncryptError(e.to_string()))?;

    let ciphertext = response
        .ciphertext_blob()
        .ok_or_else(|| KmsError::EncryptError("no ciphertext in response".to_string()))?;

    Ok(BASE64.encode(ciphertext.as_ref()))
}
