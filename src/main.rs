use std::process::exit;

use clap::{Parser, Subcommand};

use ejsonkms::actions;

#[derive(Parser)]
#[command(
    name = "ejsonkms",
    version,
    about = "manage encrypted secrets using EJSON & AWS KMS"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// (re-)encrypt one or more EJSON files
    Encrypt {
        /// EJSON file(s) to encrypt
        #[arg(value_name = "FILE", required = true)]
        files: Vec<String>,
    },
    /// decrypt an EJSON file
    Decrypt {
        /// print output to the provided file, rather than stdout
        #[arg(short = 'o', value_name = "FILE")]
        out: Option<String>,
        /// AWS Region
        #[arg(long = "aws-region", env = "AWS_REGION", default_value = "")]
        aws_region: String,
        /// EJSON file to decrypt
        #[arg(value_name = "FILE")]
        file: String,
    },
    /// generate a new EJSON keypair
    Keygen {
        /// KMS Key ID to encrypt the private key with
        #[arg(long = "kms-key-id")]
        kms_key_id: String,
        /// AWS Region
        #[arg(long = "aws-region", env = "AWS_REGION", default_value = "")]
        aws_region: String,
        /// write EJSON file to a file rather than stdout
        #[arg(short = 'o', value_name = "FILE")]
        out: Option<String>,
    },
    /// print shell export statements
    Env {
        /// Suppress export statement
        #[arg(short, long)]
        quiet: bool,
        /// AWS Region
        #[arg(long = "aws-region", env = "AWS_REGION", default_value = "")]
        aws_region: String,
        /// EJSON file to read secrets from
        #[arg(value_name = "FILE")]
        file: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { files } => {
            if let Err(err) = actions::encrypt_action(&files) {
                eprintln!("Encryption failed: {}", err);
                exit(1);
            }
        }
        Command::Decrypt {
            out,
            aws_region,
            file,
        } => {
            if let Err(err) = actions::decrypt_action(&file, &aws_region, out.as_deref()).await {
                eprintln!("Decryption failed: {}", err);
                exit(1);
            }
        }
        Command::Keygen {
            kms_key_id,
            aws_region,
            out,
        } => {
            if let Err(err) = actions::keygen_action(&kms_key_id, &aws_region, out.as_deref()).await
            {
                eprintln!("Key generation failed: {}", err);
                exit(1);
            }
        }
        Command::Env {
            quiet,
            aws_region,
            file,
        } => {
            let mut stdout = std::io::stdout();
            if let Err(err) = actions::env_action(&file, &aws_region, quiet, &mut stdout).await {
                eprintln!("error: {}", err);
                exit(1);
            }
        }
    }
}
