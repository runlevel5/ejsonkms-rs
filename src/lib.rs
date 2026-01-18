//! ejsonkms - Manage encrypted secrets using EJSON & AWS KMS
//!
//! This library combines EJSON (encrypted JSON) with AWS KMS for secure secret management.
//! The private key used for EJSON decryption is encrypted with KMS and stored in the EJSON
//! file itself, allowing secrets to be safely committed to version control.
//!
//! # Example
//!
//! ```no_run
//! use ejsonkms::{decrypt, decrypt_typed, keygen};
//!
//! # async fn example() -> Result<(), ejsonkms::EjsonKmsError> {
//! // Generate a new keypair
//! let keys = keygen("alias/my-kms-key", Some("us-east-1")).await?;
//!
//! // Decrypt an existing EJSON file (returns raw bytes)
//! let decrypted = decrypt("secrets.ejson", Some("us-east-1")).await?;
//!
//! // Or use the typed API for format-agnostic access
//! let content = decrypt_typed("secrets.ejson", Some("us-east-1")).await?;
//! if let Some(env) = content.get("environment") {
//!     if let Some(map) = env.as_string_map() {
//!         for (key, value) in map {
//!             if let Some(v) = value.as_str() {
//!                 println!("{}={}", key, v);
//!             }
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod kms;

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{fmt, fs};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use ejson::format::{FileFormat, FormatError};
pub use ejson::{DecryptedContent, DecryptedValue};
pub use kms::{decrypt_private_key_with_kms, encrypt_private_key_with_kms, KmsError};

/// A type alias for sensitive strings that are automatically zeroed on drop.
pub use zeroize::Zeroizing as SecretString;

/// Errors that can occur when working with EJSON files and KMS.
#[derive(Error, Debug)]
pub enum EjsonKmsError {
    #[error("missing _private_key_enc field")]
    MissingPrivateKeyEnc,
    #[error("{0}")]
    FormatError(#[from] FormatError),
    #[error("file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON format: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid YAML format: {0}")]
    Yaml(#[from] serde_norway::Error),
    #[error("invalid TOML format: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("invalid TOML format: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("{}", .0.user_message())]
    Kms(#[from] KmsError),
    #[error("EJSON decryption failed: {0}")]
    Ejson(String),
}

/// Keys used in an EjsonKms file.
///
/// # Security
///
/// The `private_key` field is zeroized on drop and redacted from Debug output
/// to prevent accidental exposure in logs.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EjsonKmsKeys {
    #[serde(rename = "_public_key")]
    pub public_key: String,
    #[serde(rename = "_private_key_enc")]
    pub private_key_enc: String,
    #[serde(skip)]
    pub private_key: String,
}

impl fmt::Debug for EjsonKmsKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EjsonKmsKeys")
            .field("public_key", &self.public_key)
            .field("private_key_enc", &self.private_key_enc)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Minimal structure for reading EJSON file to extract `_private_key_enc`.
#[derive(Debug, Deserialize)]
struct EjsonKmsFile {
    #[serde(rename = "_private_key_enc")]
    private_key_enc: Option<String>,
}

/// Output structure for keygen command.
///
/// # Security
///
/// Contains only encrypted/public data, but implements `Zeroize` for defense in depth.
#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
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

/// Generates a new EJSON keypair with the private key encrypted by KMS.
///
/// # Arguments
///
/// * `kms_key_id` - The KMS key ID or alias to encrypt the private key with
/// * `aws_region` - Optional AWS region override
///
/// # Returns
///
/// Returns an [`EjsonKmsKeys`] containing the public key, encrypted private key,
/// and the raw private key (for immediate use before zeroization).
pub async fn keygen(
    kms_key_id: &str,
    aws_region: Option<&str>,
) -> Result<EjsonKmsKeys, EjsonKmsError> {
    let (public_key, private_key) =
        ejson::generate_keypair().map_err(|e| EjsonKmsError::Ejson(e.to_string()))?;

    let private_key_enc =
        encrypt_private_key_with_kms(&private_key, kms_key_id, aws_region).await?;

    Ok(EjsonKmsKeys {
        public_key,
        private_key_enc,
        private_key,
    })
}

/// Decrypts an EJSON file using KMS to first decrypt the private key.
///
/// # Security
///
/// The decrypted private key is wrapped in [`Zeroizing`](zeroize::Zeroizing) for automatic
/// memory cleanup when it goes out of scope.
///
/// # Arguments
///
/// * `ejson_file_path` - Path to the EJSON file to decrypt
/// * `aws_region` - Optional AWS region override
pub async fn decrypt<P: AsRef<Path>>(
    ejson_file_path: P,
    aws_region: Option<&str>,
) -> Result<Vec<u8>, EjsonKmsError> {
    let path = ejson_file_path.as_ref();

    let private_key_enc = find_private_key_enc(path)?;
    let kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    // Decrypt the EJSON file using the decrypted private key.
    // Pass empty string for keydir since we're providing the private key directly.
    // Pass true for trim_underscore_prefix to remove leading underscore from keys.
    // The private key is automatically zeroized when kms_decrypted_private_key is dropped.
    ejson::decrypt_file(path, "", &kms_decrypted_private_key, true)
        .map_err(|e| EjsonKmsError::Ejson(e.to_string()))
}

/// Decrypts an EJSON file and returns the decrypted contents as a typed value.
///
/// This function is similar to [`decrypt`], but instead of returning raw bytes,
/// it returns a [`DecryptedContent`] enum that provides format-agnostic access to
/// the decrypted data.
///
/// This is useful for extracting specific values from the decrypted content
/// without knowing the file format.
///
/// # Security
///
/// The decrypted private key is wrapped in [`Zeroizing`](zeroize::Zeroizing) for automatic
/// memory cleanup when it goes out of scope.
///
/// # Arguments
///
/// * `ejson_file_path` - Path to the EJSON file to decrypt
/// * `aws_region` - Optional AWS region override
///
/// # Example
///
/// ```no_run
/// use ejsonkms::decrypt_typed;
///
/// # async fn example() -> Result<(), ejsonkms::EjsonKmsError> {
/// let content = decrypt_typed("secrets.ejson", Some("us-east-1")).await?;
///
/// // Access values uniformly regardless of JSON/YAML/TOML format
/// if let Some(env) = content.get("environment") {
///     if let Some(map) = env.as_string_map() {
///         for (key, value) in map {
///             if let Some(v) = value.as_str() {
///                 println!("{}={}", key, v);
///             }
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub async fn decrypt_typed<P: AsRef<Path>>(
    ejson_file_path: P,
    aws_region: Option<&str>,
) -> Result<DecryptedContent, EjsonKmsError> {
    let path = ejson_file_path.as_ref();

    // Read file once and reuse for both key extraction and decryption
    let (content, format) = read_file_with_format(path)?;

    let private_key_enc = extract_private_key_enc(&content, format)?;
    let kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    // Decrypt the EJSON content using the decrypted private key and return typed content.
    // Pass empty string for keydir since we're providing the private key directly.
    // Pass true for trim_underscore_prefix to remove leading underscore from keys.
    // The private key is automatically zeroized when kms_decrypted_private_key is dropped.
    ejson::decrypt_bytes_typed(
        content.as_bytes(),
        "",
        &kms_decrypted_private_key,
        format,
        true,
    )
    .map_err(|e| EjsonKmsError::Ejson(e.to_string()))
}

/// Finds the `_private_key_enc` field in an EJSON file.
///
/// Supports JSON, YAML, and TOML formats based on file extension.
pub fn find_private_key_enc<P: AsRef<Path>>(ejson_file_path: P) -> Result<String, EjsonKmsError> {
    let path = ejson_file_path.as_ref();
    let (content, format) = read_file_with_format(path)?;
    extract_private_key_enc(&content, format)
}

/// Reads a file and determines its format based on extension.
fn read_file_with_format<P: AsRef<Path>>(path: P) -> Result<(String, FileFormat), EjsonKmsError> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)?;
    let format = FileFormat::from_path(path)?;
    Ok((content, format))
}

/// Extracts `_private_key_enc` from content based on format.
fn extract_private_key_enc(content: &str, format: FileFormat) -> Result<String, EjsonKmsError> {
    let file: EjsonKmsFile = match format {
        FileFormat::Json => serde_json::from_str(content)?,
        FileFormat::Yaml => serde_norway::from_str(content)?,
        FileFormat::Toml => toml::from_str(content)?,
    };

    file.private_key_enc
        .filter(|s| !s.is_empty())
        .ok_or(EjsonKmsError::MissingPrivateKeyEnc)
}

#[cfg(test)]
mod tests {
    // FileFormat tests are covered in the ejson crate
    // Only ejsonkms-specific tests remain here
}
