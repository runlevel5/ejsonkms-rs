//! ejsonkms CLI - Manage encrypted secrets using EJSON & AWS KMS

use clap::{Parser, Subcommand};
use ejsonkms::{decrypt, find_private_key_enc, keygen, EjsonKmsOutput, FileFormat};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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
        /// Remove the first leading underscore from variable names
        /// (e.g., _ENVIRONMENT becomes ENVIRONMENT, __KEY becomes _KEY)
        #[arg(long = "trim-underscore-prefix")]
        trim_underscore_prefix: bool,
        /// AWS Region
        #[arg(long = "aws-region")]
        aws_region: Option<String>,
    },
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {}", message);
    ExitCode::FAILURE
}

/// Creates a file with restrictive permissions (0600 on Unix - owner read/write only)
/// This prevents other users from reading sensitive data written to the file.
#[cfg(unix)]
fn create_secure_file(path: &std::path::Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_secure_file(path: &std::path::Path) -> std::io::Result<File> {
    File::create(path)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { files } => {
            if let Err(e) = encrypt_action(&files) {
                eprintln!("Encryption failed: {}", e);
                return ExitCode::FAILURE;
            }
        }
        Commands::Decrypt {
            file,
            output,
            aws_region,
        } => {
            if let Err(e) = decrypt_action(&file, output.as_deref(), aws_region.as_deref()).await {
                eprintln!("Decryption failed: {}", e);
                return ExitCode::FAILURE;
            }
        }
        Commands::Keygen {
            kms_key_id,
            aws_region,
            output,
        } => {
            if let Err(e) =
                keygen_action(&kms_key_id, aws_region.as_deref(), output.as_deref()).await
            {
                eprintln!("Key generation failed: {}", e);
                return ExitCode::FAILURE;
            }
        }
        Commands::Env {
            file,
            quiet,
            trim_underscore_prefix,
            aws_region,
        } => {
            if let Err(e) =
                env_action(&file, aws_region.as_deref(), quiet, trim_underscore_prefix).await
            {
                return fail(&e.to_string());
            }
        }
    }

    ExitCode::SUCCESS
}

fn encrypt_action(files: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
    for file_path in files {
        let n = ejson::encrypt_file_in_place(file_path)?;
        println!("Wrote {} bytes to {}.", n, file_path.display());
    }
    Ok(())
}

async fn decrypt_action(
    file: &PathBuf,
    output: Option<&std::path::Path>,
    aws_region: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let decrypted = decrypt(file, aws_region).await?;

    match output {
        Some(out_path) => {
            let mut file = create_secure_file(out_path)?;
            file.write_all(&decrypted)?;
        }
        None => {
            io::stdout().write_all(&decrypted)?;
        }
    }

    Ok(())
}

async fn keygen_action(
    kms_key_id: &str,
    aws_region: Option<&str>,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ejson_kms_keys = keygen(kms_key_id, aws_region).await?;

    let ejson_file: EjsonKmsOutput = (&ejson_kms_keys).into();

    // Determine output format from file extension (default to JSON)
    let format = match output {
        Some(path) => FileFormat::from_path(path)?,
        None => FileFormat::default(),
    };

    let output_content = match format {
        FileFormat::Json => serde_json::to_string_pretty(&ejson_file)?,
        FileFormat::Yaml => serde_yml::to_string(&ejson_file)?,
    };

    // NOTE: Private key is intentionally NOT printed to avoid security risks.
    // The private key is encrypted and stored in the output file as _private_key_enc.
    // If you need the raw private key, decrypt _private_key_enc using KMS.

    match output {
        Some(out_path) => {
            let mut file = create_secure_file(out_path)?;
            file.write_all(output_content.as_bytes())?;
        }
        None => {
            println!("EJSON File:");
            println!("{}", output_content);
        }
    }

    Ok(())
}

async fn env_action(
    file: &PathBuf,
    aws_region: Option<&str>,
    quiet: bool,
    trim_underscore_prefix: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Find and decrypt the private key
    let private_key_enc = find_private_key_enc(file)?;
    let kms_decrypted_private_key =
        ejsonkms::decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    // Read and extract environment variables
    // Pass empty string for keydir since we're providing the private key directly
    let file_str = file.to_str().ok_or("Invalid file path")?;
    let env_values = ejson2env::read_and_extract_env(file_str, "", &kms_decrypted_private_key);

    // Handle env errors gracefully (match Go behavior)
    let env_values = match env_values {
        Ok(values) => values,
        Err(e) if ejson2env::is_env_error(&e) => {
            // No environment key or invalid - not a fatal error, just no output
            std::collections::BTreeMap::new()
        }
        Err(e) => return Err(format!("could not load environment from file: {}", e).into()),
    };

    // Apply underscore prefix trimming if requested
    let env_values = if trim_underscore_prefix {
        ejson2env::trim_underscore_prefix(&env_values)
    } else {
        env_values
    };

    // Export the environment variables
    let mut stdout = io::stdout();
    if quiet {
        ejson2env::export_quiet(&mut stdout, &env_values);
    } else {
        ejson2env::export_env(&mut stdout, &env_values);
    }

    Ok(())
}
