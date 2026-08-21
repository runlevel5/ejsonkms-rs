//! `ejsonkms` combines the [ejson](https://github.com/runlevel5/ejson-rs) library with
//! [AWS Key Management Service](https://aws.amazon.com/kms/) to simplify deployments on AWS.
//!
//! The EJSON private key is encrypted with KMS and stored inside the EJSON file as
//! `_private_key_enc`. Access to decrypt secrets can be controlled with IAM permissions
//! on the KMS key.
pub mod actions;
mod kms;

use ejson::FileFormat;
use serde::Deserialize;
use thiserror::Error;

pub(crate) use kms::{decrypt_private_key_with_kms, encrypt_private_key_with_kms};

/// Errors that can occur during ejsonkms operations.
#[derive(Error, Debug)]
pub enum EjsonKmsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_norway::Error),

    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("toml error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("utf-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("missing _private_key_enc field")]
    MissingPrivateKeyEnc,

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("{0}")]
    Kms(String),

    #[error(transparent)]
    Ejson(#[from] ejson::EjsonError),

    #[error("{0}")]
    Env(String),
}

/// Keys used in an EjsonKms file.
#[derive(Debug)]
pub struct EjsonKmsKeys {
    pub public_key: String,
    pub private_key_enc: String,
    pub private_key: String,
}

/// Generate keys and prepare an EJSON file with them.
///
/// The generated private key is encrypted with the given KMS key.
pub async fn keygen(kms_key_id: &str, aws_region: &str) -> Result<EjsonKmsKeys, EjsonKmsError> {
    let (public_key, private_key) = ejson::generate_keypair()?;

    let private_key_enc =
        encrypt_private_key_with_kms(&private_key, kms_key_id, aws_region).await?;

    Ok(EjsonKmsKeys {
        public_key,
        private_key_enc,
        private_key,
    })
}

/// Decrypt an EJSON/EYAML/ETOML file, obtaining the private key from the
/// embedded `_private_key_enc` field via KMS.
///
/// The file format is auto-detected from the file extension:
/// - `.ejson` or `.json` -> JSON format
/// - `.etoml` or `.toml` -> TOML format
/// - `.eyaml`, `.eyml`, `.yaml`, or `.yml` -> YAML format
pub async fn decrypt(ejson_file_path: &str, aws_region: &str) -> Result<Vec<u8>, EjsonKmsError> {
    let format = detect_format(ejson_file_path)?;
    let data = std::fs::read(ejson_file_path)?;

    let private_key_enc = extract_private_key_enc(&data, format)?;

    let kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    let mut output = Vec::new();
    ejson::decrypt_with_format(
        &data[..],
        &mut output,
        "",
        &kms_decrypted_private_key,
        format,
    )?;

    Ok(output)
}

/// Detect the file format from the file extension.
pub(crate) fn detect_format(file_path: &str) -> Result<FileFormat, EjsonKmsError> {
    FileFormat::from_path(file_path)
        .map_err(ejson::EjsonError::from)
        .map_err(EjsonKmsError::from)
}

#[derive(Deserialize)]
struct EjsonKmsFileFields {
    #[serde(rename = "_private_key_enc", default)]
    private_key_enc: Option<String>,
}

/// Extract the `_private_key_enc` field from raw EJSON/EYAML/ETOML file data.
pub(crate) fn extract_private_key_enc(
    data: &[u8],
    format: FileFormat,
) -> Result<String, EjsonKmsError> {
    let fields: EjsonKmsFileFields = match format {
        FileFormat::Json => serde_json::from_slice(data)?,
        FileFormat::Yaml => serde_norway::from_slice(data)?,
        FileFormat::Toml => toml::from_str(std::str::from_utf8(data)?)?,
    };

    match fields.private_key_enc {
        Some(key) if !key.is_empty() => Ok(key),
        _ => Err(EjsonKmsError::MissingPrivateKeyEnc),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_private_key_enc() {
        let data = br#"{"_public_key": "abc", "_private_key_enc": "encrypted"}"#;
        assert_eq!(
            extract_private_key_enc(data, FileFormat::Json).unwrap(),
            "encrypted"
        );
    }

    #[test]
    fn test_extract_private_key_enc_missing() {
        let data = br#"{"_public_key": "abc"}"#;
        let err = extract_private_key_enc(data, FileFormat::Json).unwrap_err();
        assert!(err.to_string().contains("missing _private_key_enc"));
    }

    #[test]
    fn test_extract_private_key_enc_empty() {
        let data = br#"{"_public_key": "abc", "_private_key_enc": ""}"#;
        let err = extract_private_key_enc(data, FileFormat::Json).unwrap_err();
        assert!(err.to_string().contains("missing _private_key_enc"));
    }

    #[test]
    fn test_extract_private_key_enc_yaml() {
        let data = b"_public_key: abc\n_private_key_enc: encrypted\n";
        assert_eq!(
            extract_private_key_enc(data, FileFormat::Yaml).unwrap(),
            "encrypted"
        );

        let missing = b"_public_key: abc\n";
        assert!(matches!(
            extract_private_key_enc(missing, FileFormat::Yaml),
            Err(EjsonKmsError::MissingPrivateKeyEnc)
        ));
    }

    #[test]
    fn test_extract_private_key_enc_toml() {
        let data = b"_public_key = \"abc\"\n_private_key_enc = \"encrypted\"\n";
        assert_eq!(
            extract_private_key_enc(data, FileFormat::Toml).unwrap(),
            "encrypted"
        );

        let missing = b"_public_key = \"abc\"\n";
        assert!(matches!(
            extract_private_key_enc(missing, FileFormat::Toml),
            Err(EjsonKmsError::MissingPrivateKeyEnc)
        ));
    }

    #[test]
    fn test_extract_private_key_enc_from_testdata() {
        let data = std::fs::read("testdata/test.ejson").unwrap();
        let key = extract_private_key_enc(&data, FileFormat::Json).unwrap();
        assert!(key.starts_with("S2Fybjphd3M6a21z"));
    }

    #[test]
    fn test_extract_private_key_enc_missing_in_testdata() {
        let data = std::fs::read("testdata/test_no_private_key.ejson").unwrap();
        assert!(matches!(
            extract_private_key_enc(&data, FileFormat::Json),
            Err(EjsonKmsError::MissingPrivateKeyEnc)
        ));
    }

    #[test]
    fn test_detect_format() {
        assert_eq!(detect_format("a.ejson").unwrap(), FileFormat::Json);
        assert_eq!(detect_format("a.eyaml").unwrap(), FileFormat::Yaml);
        assert_eq!(detect_format("a.etoml").unwrap(), FileFormat::Toml);
        assert!(detect_format("a.txt").is_err());
    }
}
