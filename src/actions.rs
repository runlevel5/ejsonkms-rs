//! CLI actions for the `ejsonkms` binary.

use std::io::Write;

use serde::Serialize;

use ejson::FileFormat;

use crate::{
    decrypt, decrypt_private_key_with_kms, detect_format, extract_private_key_enc, keygen,
    EjsonKmsError,
};

/// (Re-)encrypt one or more EJSON files in place.
pub fn encrypt_action(file_paths: &[String]) -> Result<(), EjsonKmsError> {
    if file_paths.is_empty() {
        return Err(EjsonKmsError::Env(
            "at least one file path must be given".to_string(),
        ));
    }
    for file_path in file_paths {
        let n = ejson::encrypt_file_in_place(file_path)?;
        println!("Wrote {} bytes to {}.", n, file_path);
    }
    Ok(())
}

/// Decrypt an EJSON file, writing the output to `out_file` (or stdout if `None`).
pub async fn decrypt_action(
    ejson_file_path: &str,
    aws_region: &str,
    out_file: Option<&str>,
) -> Result<(), EjsonKmsError> {
    let decrypted = decrypt(ejson_file_path, aws_region).await?;

    match out_file {
        Some(path) => {
            let mut target = std::fs::File::create(path)?;
            target.write_all(&decrypted)?;
        }
        None => {
            std::io::stdout().write_all(&decrypted)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct EjsonKmsFile {
    #[serde(rename = "_public_key")]
    public_key: String,
    #[serde(rename = "_private_key_enc")]
    private_key_enc: String,
}

/// Generate a new EJSON keypair, encrypting the private key with KMS.
///
/// Prints the private key to stdout and writes the EJSON file to `out_file`
/// (or stdout if `None`).
///
/// The output format follows the extension of `out_file` (`.eyaml` -> YAML,
/// `.etoml` -> TOML, ...); JSON is used for stdout or unrecognized extensions.
pub async fn keygen_action(
    kms_key_id: &str,
    aws_region: &str,
    out_file: Option<&str>,
) -> Result<(), EjsonKmsError> {
    let ejson_kms_keys = keygen(kms_key_id, aws_region).await?;

    let ejson_kms_file = EjsonKmsFile {
        public_key: ejson_kms_keys.public_key,
        private_key_enc: ejson_kms_keys.private_key_enc,
    };

    let format = out_file
        .and_then(|path| detect_format(path).ok())
        .unwrap_or(FileFormat::Json);
    let ejson_file = match format {
        FileFormat::Json => serde_json::to_string_pretty(&ejson_kms_file)?,
        FileFormat::Yaml => serde_norway::to_string(&ejson_kms_file)?,
        FileFormat::Toml => toml::to_string(&ejson_kms_file)?,
    };

    println!("Private Key: {}", ejson_kms_keys.private_key);
    match out_file {
        Some(path) => {
            let mut target = std::fs::File::create(path)?;
            target.write_all(ejson_file.as_bytes())?;
        }
        None => {
            println!("EJSON File:");
            std::io::stdout().write_all(ejson_file.as_bytes())?;
        }
    }
    Ok(())
}

/// Decrypt an EJSON file and write shell export statements for the values
/// under its `environment` key.
pub async fn env_action<W: Write>(
    ejson_file_path: &str,
    aws_region: &str,
    quiet: bool,
    output: &mut W,
) -> Result<(), EjsonKmsError> {
    let export_func: ejson::env::ExportFunction = if quiet {
        ejson::env::export_quiet
    } else {
        ejson::env::export_env
    };

    let format = detect_format(ejson_file_path)?;

    // Read the file once
    let data = std::fs::read(ejson_file_path)?;

    let private_key_enc = extract_private_key_enc(&data, format)?;

    let kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    // Decrypt using the already-read data
    let content = ejson::decrypt_bytes_typed(&data, "", &kms_decrypted_private_key, format, false)?;

    // Extract env values; a missing or invalid "environment" key results in an
    // empty export rather than an error
    let env_values = match ejson::env::extract_env(&content) {
        Ok(values) => values,
        Err(e) if ejson::env::is_env_error(&e) => ejson::env::SecretEnvMap::new(),
        Err(e) => {
            return Err(EjsonKmsError::Env(format!(
                "could not load environment from file: {}",
                e
            )))
        }
    };

    export_func(output, &env_values).map_err(|e| EjsonKmsError::Env(e.to_string()))
}
