//! Tests for underscore prefix trimming behavior during decryption
//!
//! These tests verify that leading underscores are properly trimmed from keys
//! at all nesting levels, not just top-level keys.

use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to create a test EJSON file with the given content
fn create_test_file(content: &str, extension: &str) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(extension)
        .tempfile()
        .expect("Failed to create temp file");
    file.write_all(content.as_bytes())
        .expect("Failed to write to temp file");
    file
}

/// Generate a fresh keypair for testing
fn generate_test_keypair() -> (String, String) {
    ejson::generate_keypair().expect("Failed to generate keypair")
}

/// Test that underscore prefixes are trimmed from nested keys under "environment"
/// when using ejson::decrypt_file with trim_underscore_prefix=true
#[test]
fn test_nested_underscore_prefix_trimming_in_environment() {
    let (public_key, private_key) = generate_test_keypair();

    // Create a test file with underscore-prefixed keys in environment
    let json_content = format!(
        r#"{{
  "_public_key": "{public_key}",
  "environment": {{
    "_DATABASE_HOST": "localhost",
    "_DATABASE_PORT": "5432",
    "__DOUBLE_UNDERSCORE": "value",
    "NORMAL_KEY": "normal_value"
  }}
}}"#
    );

    let file = create_test_file(&json_content, ".ejson");

    // Encrypt the file first
    ejson::encrypt_file_in_place(file.path()).expect("Failed to encrypt file");

    // Now decrypt with trim_underscore_prefix=true
    let decrypted =
        ejson::decrypt_file(file.path(), "", &private_key, true).expect("Failed to decrypt file");

    let decrypted_str = String::from_utf8(decrypted).expect("Invalid UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(&decrypted_str).expect("Failed to parse decrypted JSON");

    // Verify the environment keys have been trimmed
    let env = parsed
        .get("environment")
        .expect("environment key should exist");

    // _DATABASE_HOST should become DATABASE_HOST
    assert!(
        env.get("DATABASE_HOST").is_some(),
        "Key _DATABASE_HOST should be trimmed to DATABASE_HOST, got keys: {:?}",
        env.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    assert_eq!(
        env.get("DATABASE_HOST").and_then(|v| v.as_str()),
        Some("localhost")
    );

    // _DATABASE_PORT should become DATABASE_PORT
    assert!(
        env.get("DATABASE_PORT").is_some(),
        "Key _DATABASE_PORT should be trimmed to DATABASE_PORT"
    );
    assert_eq!(
        env.get("DATABASE_PORT").and_then(|v| v.as_str()),
        Some("5432")
    );

    // __DOUBLE_UNDERSCORE should become _DOUBLE_UNDERSCORE (only first underscore removed)
    assert!(
        env.get("_DOUBLE_UNDERSCORE").is_some(),
        "Key __DOUBLE_UNDERSCORE should be trimmed to _DOUBLE_UNDERSCORE"
    );
    assert_eq!(
        env.get("_DOUBLE_UNDERSCORE").and_then(|v| v.as_str()),
        Some("value")
    );

    // NORMAL_KEY should remain unchanged
    assert!(
        env.get("NORMAL_KEY").is_some(),
        "Key NORMAL_KEY should remain unchanged"
    );
    assert_eq!(
        env.get("NORMAL_KEY").and_then(|v| v.as_str()),
        Some("normal_value")
    );

    // Original underscore-prefixed keys should NOT exist
    assert!(
        env.get("_DATABASE_HOST").is_none(),
        "Original key _DATABASE_HOST should not exist after trimming"
    );
    assert!(
        env.get("_DATABASE_PORT").is_none(),
        "Original key _DATABASE_PORT should not exist after trimming"
    );
    assert!(
        env.get("__DOUBLE_UNDERSCORE").is_none(),
        "Original key __DOUBLE_UNDERSCORE should not exist after trimming"
    );
}

/// Test that underscore prefixes are trimmed from deeply nested keys
#[test]
fn test_deeply_nested_underscore_prefix_trimming() {
    let (public_key, private_key) = generate_test_keypair();

    let json_content = format!(
        r#"{{
  "_public_key": "{public_key}",
  "config": {{
    "database": {{
      "_host": "db.example.com",
      "_port": "3306",
      "credentials": {{
        "_username": "admin",
        "_password": "secret123"
      }}
    }}
  }}
}}"#
    );

    let file = create_test_file(&json_content, ".ejson");

    // Encrypt the file first
    ejson::encrypt_file_in_place(file.path()).expect("Failed to encrypt file");

    // Decrypt with trim_underscore_prefix=true
    let decrypted =
        ejson::decrypt_file(file.path(), "", &private_key, true).expect("Failed to decrypt file");

    let decrypted_str = String::from_utf8(decrypted).expect("Invalid UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(&decrypted_str).expect("Failed to parse decrypted JSON");

    // Verify deeply nested keys have been trimmed
    let db = parsed
        .get("config")
        .and_then(|c| c.get("database"))
        .expect("config.database should exist");

    // _host should become host
    assert!(
        db.get("host").is_some(),
        "Key _host should be trimmed to host, got keys: {:?}",
        db.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    assert_eq!(
        db.get("host").and_then(|v| v.as_str()),
        Some("db.example.com")
    );

    // _port should become port
    assert!(
        db.get("port").is_some(),
        "Key _port should be trimmed to port"
    );
    assert_eq!(db.get("port").and_then(|v| v.as_str()), Some("3306"));

    // Check deeply nested credentials
    let creds = db.get("credentials").expect("credentials should exist");

    // _username should become username
    assert!(
        creds.get("username").is_some(),
        "Key _username should be trimmed to username, got keys: {:?}",
        creds.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    assert_eq!(
        creds.get("username").and_then(|v| v.as_str()),
        Some("admin")
    );

    // _password should become password
    assert!(
        creds.get("password").is_some(),
        "Key _password should be trimmed to password"
    );
    assert_eq!(
        creds.get("password").and_then(|v| v.as_str()),
        Some("secret123")
    );

    // Original underscore-prefixed keys should NOT exist
    assert!(
        db.get("_host").is_none(),
        "Original key _host should not exist after trimming"
    );
    assert!(
        db.get("_port").is_none(),
        "Original key _port should not exist after trimming"
    );
    assert!(
        creds.get("_username").is_none(),
        "Original key _username should not exist after trimming"
    );
    assert!(
        creds.get("_password").is_none(),
        "Original key _password should not exist after trimming"
    );
}

/// Test YAML format with nested underscore prefixes
#[test]
fn test_yaml_nested_underscore_prefix_trimming() {
    let (public_key, private_key) = generate_test_keypair();

    let yaml_content = format!(
        r#"_public_key: "{public_key}"
environment:
  _DATABASE_HOST: "localhost"
  _DATABASE_PORT: "5432"
  _API_KEY: "secret_api_key"
"#
    );

    let file = create_test_file(&yaml_content, ".yaml");

    // Encrypt the file first
    ejson::encrypt_file_in_place(file.path()).expect("Failed to encrypt YAML file");

    // Decrypt with trim_underscore_prefix=true
    let decrypted =
        ejson::decrypt_file(file.path(), "", &private_key, true).expect("Failed to decrypt file");

    let decrypted_str = String::from_utf8(decrypted).expect("Invalid UTF-8");
    let parsed: serde_yml::Value =
        serde_yml::from_str(&decrypted_str).expect("Failed to parse decrypted YAML");

    // Verify the environment keys have been trimmed
    let env = parsed
        .get("environment")
        .expect("environment key should exist");

    assert!(
        env.get("DATABASE_HOST").is_some(),
        "Key _DATABASE_HOST should be trimmed to DATABASE_HOST in YAML, got keys: {:?}",
        env
    );
    assert!(
        env.get("DATABASE_PORT").is_some(),
        "Key _DATABASE_PORT should be trimmed to DATABASE_PORT in YAML"
    );
    assert!(
        env.get("API_KEY").is_some(),
        "Key _API_KEY should be trimmed to API_KEY in YAML"
    );

    // Original underscore-prefixed keys should NOT exist
    assert!(
        env.get("_DATABASE_HOST").is_none(),
        "Original key _DATABASE_HOST should not exist after trimming in YAML"
    );
}

/// Test TOML format with nested underscore prefixes
#[test]
fn test_toml_nested_underscore_prefix_trimming() {
    let (public_key, private_key) = generate_test_keypair();

    let toml_content = format!(
        r#"_public_key = "{public_key}"

[environment]
_DATABASE_HOST = "localhost"
_DATABASE_PORT = "5432"
_API_KEY = "secret_api_key"
"#
    );

    let file = create_test_file(&toml_content, ".toml");

    // Encrypt the file first
    ejson::encrypt_file_in_place(file.path()).expect("Failed to encrypt TOML file");

    // Decrypt with trim_underscore_prefix=true
    let decrypted =
        ejson::decrypt_file(file.path(), "", &private_key, true).expect("Failed to decrypt file");

    let decrypted_str = String::from_utf8(decrypted).expect("Invalid UTF-8");
    let parsed: toml::Value =
        toml::from_str(&decrypted_str).expect("Failed to parse decrypted TOML");

    // Verify the environment keys have been trimmed
    let env = parsed
        .get("environment")
        .expect("environment key should exist");

    assert!(
        env.get("DATABASE_HOST").is_some(),
        "Key _DATABASE_HOST should be trimmed to DATABASE_HOST in TOML, got keys: {:?}",
        env.as_table().map(|t| t.keys().collect::<Vec<_>>())
    );
    assert!(
        env.get("DATABASE_PORT").is_some(),
        "Key _DATABASE_PORT should be trimmed to DATABASE_PORT in TOML"
    );
    assert!(
        env.get("API_KEY").is_some(),
        "Key _API_KEY should be trimmed to API_KEY in TOML"
    );

    // Original underscore-prefixed keys should NOT exist
    assert!(
        env.get("_DATABASE_HOST").is_none(),
        "Original key _DATABASE_HOST should not exist after trimming in TOML"
    );
}

/// Debug test to show actual input/output of underscore prefix trimming
#[test]
fn test_debug_underscore_trimming_output() {
    let (public_key, private_key) = generate_test_keypair();

    // Create a test file with underscore-prefixed keys in environment
    let json_content = format!(
        r#"{{
  "_public_key": "{public_key}",
  "environment": {{
    "_DATABASE_HOST": "localhost",
    "_DATABASE_PORT": "5432",
    "__DOUBLE_UNDERSCORE": "double_value",
    "NORMAL_KEY": "normal_value"
  }},
  "top_level": {{
    "_nested_key": "nested_value"
  }}
}}"#
    );

    println!("\n=== ORIGINAL (before encryption) ===");
    println!("{}", json_content);

    let file = create_test_file(&json_content, ".ejson");

    // Encrypt the file
    ejson::encrypt_file_in_place(file.path()).expect("Failed to encrypt file");

    let encrypted_content =
        std::fs::read_to_string(file.path()).expect("Failed to read encrypted file");
    println!("\n=== ENCRYPTED ===");
    println!("{}", encrypted_content);

    // Decrypt with trim_underscore_prefix=true
    let decrypted =
        ejson::decrypt_file(file.path(), "", &private_key, true).expect("Failed to decrypt file");
    let decrypted_str = String::from_utf8(decrypted).expect("Invalid UTF-8");

    println!("\n=== DECRYPTED (trim_underscore_prefix=true) ===");
    println!("{}", decrypted_str);

    // Also show with trim_underscore_prefix=false for comparison
    let decrypted_no_trim =
        ejson::decrypt_file(file.path(), "", &private_key, false).expect("Failed to decrypt file");
    let decrypted_no_trim_str = String::from_utf8(decrypted_no_trim).expect("Invalid UTF-8");

    println!("\n=== DECRYPTED (trim_underscore_prefix=false) ===");
    println!("{}", decrypted_no_trim_str);
}

/// Test that trim_underscore_prefix=false preserves the original keys
#[test]
fn test_no_trimming_when_disabled() {
    let (public_key, private_key) = generate_test_keypair();

    let json_content = format!(
        r#"{{
  "_public_key": "{public_key}",
  "environment": {{
    "_DATABASE_HOST": "localhost",
    "_DATABASE_PORT": "5432"
  }}
}}"#
    );

    let file = create_test_file(&json_content, ".ejson");

    // Encrypt the file first
    ejson::encrypt_file_in_place(file.path()).expect("Failed to encrypt file");

    // Decrypt with trim_underscore_prefix=false
    let decrypted =
        ejson::decrypt_file(file.path(), "", &private_key, false).expect("Failed to decrypt file");

    let decrypted_str = String::from_utf8(decrypted).expect("Invalid UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(&decrypted_str).expect("Failed to parse decrypted JSON");

    let env = parsed
        .get("environment")
        .expect("environment key should exist");

    // When trimming is disabled, original keys should be preserved
    assert!(
        env.get("_DATABASE_HOST").is_some(),
        "Original key _DATABASE_HOST should be preserved when trimming is disabled"
    );
    assert!(
        env.get("_DATABASE_PORT").is_some(),
        "Original key _DATABASE_PORT should be preserved when trimming is disabled"
    );

    // Trimmed keys should NOT exist
    assert!(
        env.get("DATABASE_HOST").is_none(),
        "Trimmed key DATABASE_HOST should not exist when trimming is disabled"
    );
    assert!(
        env.get("DATABASE_PORT").is_none(),
        "Trimmed key DATABASE_PORT should not exist when trimming is disabled"
    );
}
