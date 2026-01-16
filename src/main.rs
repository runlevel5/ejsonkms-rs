//! ejsonkms CLI - Manage encrypted secrets using EJSON & AWS KMS

use clap::{Parser, Subcommand};
use ejsonkms::{decrypt, find_private_key_enc, keygen, EjsonKmsError, EjsonKmsOutput, FileFormat};
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// CLI-specific errors that wrap library errors with context
#[derive(Error, Debug)]
enum CliError {
    #[error("encryption failed: {0}")]
    Encryption(#[from] ejson::EjsonError),
    #[error("decryption failed: {0}")]
    Decryption(#[from] EjsonKmsError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yml::Error),
    #[error("TOML serialization error: {0}")]
    Toml(#[from] toml::ser::Error),
    #[error("unsupported file format: {0}")]
    Format(#[from] ejsonkms::FormatError),
    #[error("KMS error: {}", .0.user_message())]
    Kms(#[from] ejsonkms::KmsError),
    #[error("invalid UTF-8 in file path")]
    InvalidPath,
}

/// Manage encrypted secrets using EJSON & AWS KMS
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// (Re-)encrypt one or more EJSON files
    Encrypt {
        /// EJSON files to encrypt
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Decrypt an EJSON file
    Decrypt {
        /// EJSON file to decrypt
        file: PathBuf,
        /// Print output to the provided file, rather than stdout
        #[arg(short = 'o')]
        output: Option<PathBuf>,
        /// AWS Region
        #[arg(long = "aws-region")]
        aws_region: Option<String>,
    },
    /// Generate a new EJSON keypair
    Keygen {
        /// KMS Key ID to encrypt the private key with
        #[arg(long = "kms-key-id", required = true)]
        kms_key_id: String,
        /// AWS Region
        #[arg(long = "aws-region")]
        aws_region: Option<String>,
        /// Write EJSON file to a file rather than stdout
        #[arg(short = 'o')]
        output: Option<PathBuf>,
    },
    /// Print shell export statements
    Env {
        /// EJSON file to read
        file: PathBuf,
        /// Suppress export statement
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// AWS Region
        #[arg(long = "aws-region")]
        aws_region: Option<String>,
    },
}

fn fail(err: impl std::fmt::Display) -> ExitCode {
    eprintln!("error: {err}");
    ExitCode::FAILURE
}

/// Creates a file with restrictive permissions (0600 on Unix - owner read/write only)
/// This prevents other users from reading sensitive data written to the file.
#[cfg(unix)]
fn create_secure_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

/// Creates a file with restrictive permissions on Windows.
/// Uses SECURITY_ATTRIBUTES to restrict access to the current user only.
#[cfg(windows)]
fn create_secure_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_ATTRIBUTE_NORMAL with restricted sharing mode
    // Note: For full security on Windows, consider using the windows-acl crate
    // to set explicit ACLs. This implementation provides basic protection.
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .share_mode(0) // Deny sharing while file is open
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn create_secure_file(path: &Path) -> std::io::Result<File> {
    // Fallback for other platforms - warn user about potential security issue
    eprintln!("warning: secure file permissions not implemented for this platform");
    File::create(path)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt { files } => encrypt_action(&files).map_err(Into::into),
        Commands::Decrypt {
            file,
            output,
            aws_region,
        } => decrypt_action(&file, output.as_deref(), aws_region.as_deref()).await,
        Commands::Keygen {
            kms_key_id,
            aws_region,
            output,
        } => keygen_action(&kms_key_id, aws_region.as_deref(), output.as_deref()).await,
        Commands::Env {
            file,
            quiet,
            aws_region,
        } => env_action(&file, aws_region.as_deref(), quiet).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

fn encrypt_action(files: &[PathBuf]) -> Result<(), ejson::EjsonError> {
    for file_path in files {
        let n = ejson::encrypt_file_in_place(file_path)?;
        println!("Wrote {n} bytes to {}.", file_path.display());
    }
    Ok(())
}

async fn decrypt_action(
    file: &Path,
    output: Option<&Path>,
    aws_region: Option<&str>,
) -> Result<(), CliError> {
    let decrypted = decrypt(file, aws_region).await?;

    if let Some(out_path) = output {
        let mut file = create_secure_file(out_path)?;
        file.write_all(&decrypted)?;
    } else {
        // Security warning: warn users when outputting secrets to a terminal
        if io::stdout().is_terminal() {
            eprintln!("warning: writing secrets to terminal; consider using -o to write to a file");
        }
        io::stdout().write_all(&decrypted)?;
    }

    Ok(())
}

async fn keygen_action(
    kms_key_id: &str,
    aws_region: Option<&str>,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let ejson_kms_keys = keygen(kms_key_id, aws_region).await?;
    let ejson_file = EjsonKmsOutput::from(&ejson_kms_keys);

    // Determine output format from file extension (default to JSON)
    let format = output
        .map(FileFormat::from_path)
        .transpose()?
        .unwrap_or_default();

    let output_content = match format {
        FileFormat::Json => serde_json::to_string_pretty(&ejson_file)?,
        FileFormat::Yaml => serde_yml::to_string(&ejson_file)?,
        FileFormat::Toml => toml::to_string_pretty(&ejson_file)?,
    };

    // NOTE: Private key is intentionally NOT printed to avoid security risks.
    // The private key is encrypted and stored in the output file as _private_key_enc.
    // If you need the raw private key, decrypt _private_key_enc using KMS.

    if let Some(out_path) = output {
        let mut file = create_secure_file(out_path)?;
        file.write_all(output_content.as_bytes())?;
    } else {
        println!("EJSON File:");
        println!("{output_content}");
    }

    Ok(())
}

async fn env_action(file: &Path, aws_region: Option<&str>, quiet: bool) -> Result<(), CliError> {
    // Find and decrypt the private key (returns Zeroizing<String> for automatic cleanup)
    let private_key_enc = find_private_key_enc(file)?;
    let kms_decrypted_private_key =
        ejsonkms::decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    // Read and extract environment variables
    // Pass empty string for keydir since we're providing the private key directly
    // Pass true for trim_underscore_prefix to trim underscore prefix from variable names
    // (e.g., _DATABASE_HOST becomes DATABASE_HOST, __KEY becomes _KEY)
    // The private key is automatically zeroized when kms_decrypted_private_key is dropped
    let file_str = file.to_str().ok_or(CliError::InvalidPath)?;
    let env_values =
        ejson2env::read_and_extract_env(file_str, "", &kms_decrypted_private_key, true)
            .unwrap_or_else(|e| {
                if ejson2env::is_env_error(&e) {
                    // No environment key or invalid - not a fatal error, just no output
                    ejson2env::SecretEnvMap::new()
                } else {
                    // Log non-env errors (decryption failures, file errors, etc.) for debugging
                    eprintln!("warning: failed to extract environment variables: {e}");
                    ejson2env::SecretEnvMap::new()
                }
            });

    // Export the environment variables
    let mut stdout = io::stdout();
    if quiet {
        ejson2env::export_quiet(&mut stdout, &env_values);
    } else {
        ejson2env::export_env(&mut stdout, &env_values);
    }

    Ok(())
}
