//! ejsonkms - Manage encrypted secrets using EJSON & AWS KMS
//!
//! This library combines EJSON (encrypted JSON) with AWS KMS for secure secret management.
//! The private key used for EJSON decryption is encrypted with KMS and stored in the EJSON
//! file itself, allowing secrets to be safely committed to version control.

pub mod kms;

use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use kms::{decrypt_private_key_with_kms, encrypt_private_key_with_kms, KmsError};

/// Supported file formats for EJSON files
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileFormat {
    #[default]
    Json,
    Yaml,
    Toml,
}

impl FileFormat {
    /// Detect the file format from a file path based on extension
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, EjsonKmsError> {
        match path.as_ref().extension().and_then(OsStr::to_str) {
            Some("eyaml") | Some("eyml") | Some("yaml") | Some("yml") => Ok(FileFormat::Yaml),
            Some("ejson") | Some("json") => Ok(FileFormat::Json),
            Some("etoml") | Some("toml") => Ok(FileFormat::Toml),
            Some(ext) => Err(EjsonKmsError::UnsupportedFileExtension(ext.to_string())),
            None => Err(EjsonKmsError::UnsupportedFileExtension(
                "(none)".to_string(),
            )),
        }
    }

    /// Get the file extension for this format
    pub fn extension(&self) -> &'static str {
        match self {
            FileFormat::Json => "ejson",
            FileFormat::Yaml => "eyaml",
            FileFormat::Toml => "etoml",
        }
    }
}

#[derive(Error, Debug)]
pub enum EjsonKmsError {
    #[error("missing _private_key_enc field")]
    MissingPrivateKeyEnc,
    #[error("unsupported file extension: {0}")]
    UnsupportedFileExtension(String),
    #[error("file error")]
    IoError(#[from] std::io::Error),
    #[error("invalid JSON format")]
    JsonError(#[from] serde_json::Error),
    #[error("invalid YAML format")]
    YamlError(#[from] serde_yml::Error),
    #[error("invalid TOML format: {0}")]
    TomlDeError(#[from] toml::de::Error),
    #[error("invalid TOML format: {0}")]
    TomlSerError(#[from] toml::ser::Error),
    #[error("{}", .0.user_message())]
    KmsError(#[from] KmsError),
    #[error("decryption failed")]
    EjsonError(String),
}

/// Keys used in an EjsonKms file
///
/// Security: The private_key field is zeroized on drop and redacted from Debug output
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EjsonKmsKeys {
    #[serde(rename = "_public_key")]
    pub public_key: String,
    #[serde(rename = "_private_key_enc")]
    pub private_key_enc: String,
    #[serde(skip)]
    pub private_key: String,
}

// Custom Debug implementation that redacts sensitive fields
impl fmt::Debug for EjsonKmsKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EjsonKmsKeys")
            .field("public_key", &self.public_key)
            .field("private_key_enc", &self.private_key_enc)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Minimal structure for reading EJSON file to extract _private_key_enc
#[derive(Debug, Deserialize)]
struct EjsonKmsFile {
    #[serde(rename = "_private_key_enc")]
    private_key_enc: Option<String>,
}

/// Output structure for keygen (matches the Go version)
///
/// Security: Contains only encrypted/public data, but implements Zeroize for defense in depth
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
///
/// Security: The decrypted private key is zeroized after use to prevent sensitive
/// data from lingering in memory.
pub async fn decrypt<P: AsRef<Path>>(
    ejson_file_path: P,
    aws_region: Option<&str>,
) -> Result<Vec<u8>, EjsonKmsError> {
    let path = ejson_file_path.as_ref();

    // Find the encrypted private key in the file
    let private_key_enc = find_private_key_enc(path)?;

    // Decrypt the private key using KMS
    let mut kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    // Decrypt the EJSON file using the decrypted private key
    // Pass empty string for keydir since we're providing the private key directly
    let decrypted = ejson::decrypt_file(path, "", &kms_decrypted_private_key)
        .map_err(|e| EjsonKmsError::EjsonError(e.to_string()));

    // Zeroize the decrypted private key immediately after use
    kms_decrypted_private_key.zeroize();

    decrypted
}

/// Finds the _private_key_enc field in an EJSON file (supports JSON and YAML)
pub fn find_private_key_enc<P: AsRef<Path>>(ejson_file_path: P) -> Result<String, EjsonKmsError> {
    let path = ejson_file_path.as_ref();
    let content = fs::read_to_string(path)?;
    let format = FileFormat::from_path(path)?;

    let file: EjsonKmsFile = match format {
        FileFormat::Json => serde_json::from_str(&content)?,
        FileFormat::Yaml => serde_yml::from_str(&content)?,
        FileFormat::Toml => toml::from_str(&content)?,
    };

    file.private_key_enc
        .filter(|s| !s.is_empty())
        .ok_or(EjsonKmsError::MissingPrivateKeyEnc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_path_json_extensions() {
        assert_eq!(
            FileFormat::from_path("file.json").unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            FileFormat::from_path("file.ejson").unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.json").unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.ejson").unwrap(),
            FileFormat::Json
        );
    }

    #[test]
    fn test_from_path_yaml_extensions() {
        assert_eq!(
            FileFormat::from_path("file.yaml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(FileFormat::from_path("file.yml").unwrap(), FileFormat::Yaml);
        assert_eq!(
            FileFormat::from_path("file.eyaml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            FileFormat::from_path("file.eyml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.eyaml").unwrap(),
            FileFormat::Yaml
        );
    }

    #[test]
    fn test_from_path_toml_extensions() {
        assert_eq!(
            FileFormat::from_path("file.toml").unwrap(),
            FileFormat::Toml
        );
        assert_eq!(
            FileFormat::from_path("file.etoml").unwrap(),
            FileFormat::Toml
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.toml").unwrap(),
            FileFormat::Toml
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.etoml").unwrap(),
            FileFormat::Toml
        );
    }

    #[test]
    fn test_from_path_unsupported_extension() {
        let err = FileFormat::from_path("file.txt").unwrap_err();
        assert!(matches!(err, EjsonKmsError::UnsupportedFileExtension(ext) if ext == "txt"));

        let err = FileFormat::from_path("file.xml").unwrap_err();
        assert!(matches!(err, EjsonKmsError::UnsupportedFileExtension(ext) if ext == "xml"));
    }

    #[test]
    fn test_from_path_no_extension() {
        let err = FileFormat::from_path("file").unwrap_err();
        assert!(matches!(err, EjsonKmsError::UnsupportedFileExtension(ext) if ext == "(none)"));

        let err = FileFormat::from_path("path/to/file").unwrap_err();
        assert!(matches!(err, EjsonKmsError::UnsupportedFileExtension(ext) if ext == "(none)"));
    }

    #[test]
    fn test_file_format_extension() {
        assert_eq!(FileFormat::Json.extension(), "ejson");
        assert_eq!(FileFormat::Yaml.extension(), "eyaml");
        assert_eq!(FileFormat::Toml.extension(), "etoml");
    }

    #[test]
    fn test_file_format_default() {
        assert_eq!(FileFormat::default(), FileFormat::Json);
    }
}
