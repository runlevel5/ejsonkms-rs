# ejsonkms-rs

A Rust implementation of [envato/ejsonkms](https://github.com/envato/ejsonkms). This is a drop-in replacement for the original Go implementation, with support for **YAML** and **TOML** file formats.

 `ejsonkms` combines the [ejson](https://github.com/runlevel5/ejson-rs) and [ejson2env](https://github.com/runlevel5/ejson2env-rs) libraries with [AWS Key Management Service](https://aws.amazon.com/kms/) to simplify deployments on AWS. The EJSON private key is encrypted with KMS and stored inside the EJSON file as `_private_key_enc`. Access to decrypt secrets can be controlled with IAM permissions on the KMS key.

## Supported File Formats

| Format | Extensions | Status |
|--------|------------|--------|
| JSON   | `.ejson`, `.json` | Supported |
| YAML   | `.eyaml`, `.eyml`, `.yaml`, `.yml` | Supported |
| TOML   | `.etoml`, `.toml` | Supported |

The file format is automatically detected based on the file extension.

## Installation

### Pre-built Binaries

Download compiled binaries from [Releases](https://github.com/runlevel5/ejsonkms-rs/releases).

### Build from Source

```shell
git clone https://github.com/runlevel5/ejsonkms-rs.git
cd ejson-rs
cargo build --release
cp ./target/release/ejsonkms ~/.local/bin/
```

## Usage

Generating an EJSON file:

```shell
$ ejsonkms keygen --aws-region us-east-1 --kms-key-id bc436485-5092-42b8-92a3-0aa8b93536dc -o secrets.ejson
$ cat secrets.ejson
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q=="
}
```

> **Security Note:** The raw private key is never printed to the console. The private key is encrypted with KMS and stored as `_private_key_enc` in the output file.

To generate a YAML file instead, use a `.eyaml` or `.eyml` extension:

```shell
$ ejsonkms keygen --aws-region us-east-1 --kms-key-id bc436485-5092-42b8-92a3-0aa8b93536dc -o secrets.eyaml
$ cat secrets.eyaml
_public_key: 6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52
_private_key_enc: S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q==
```

Encrypting:

```shell
$ ejsonkms encrypt secrets.ejson
```

Adding secrets and non-secrets to the `environment` attribute:

The `environment` attribute is where you store your configuration values. There are two types of values:

- **Secrets** - Keys without an underscore prefix will be encrypted when you run `ejsonkms encrypt`
- **Non-secrets** - Keys prefixed with `_` (underscore) will remain in plaintext and won't be encrypted

```shell
# Edit your secrets.ejson file and add values to the environment attribute:
$ cat secrets.ejson
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q==",
  "secret_1": "supersecretpassword",
  "_non_secret_1": "cleartext",
  "environment": {
    "DATABASE_PASSWORD": "supersecretpassword",
    "API_KEY": "sk-1234567890abcdef",
    "JWT_SECRET": "my-jwt-signing-key",
    "_DATABASE_HOST": "db.example.com",
    "_DATABASE_PORT": "5432",
    "_APP_ENV": "production"
  }
}
```

After running `ejsonkms encrypt secrets.ejson`, the file will look like:

```json
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q==",
  "secret_1": "EJ[1:ZH5kC...encrypted...]:...",
  "_non_secret_1": "cleartext",
  "environment": {
    "DATABASE_PASSWORD": "EJ[1:ZH5kC...encrypted...]:...",
    "API_KEY": "EJ[1:AB3xY...encrypted...]:...",
    "JWT_SECRET": "EJ[1:CD7zW...encrypted...]:...",
    "_DATABASE_HOST": "db.example.com",
    "_DATABASE_PORT": "5432",
    "_APP_ENV": "production"
  }
}
```

Notice that:
- `DATABASE_PASSWORD`, `API_KEY`, and `JWT_SECRET` are now encrypted (values starting with `EJ[...`)
- `_DATABASE_HOST`, `_DATABASE_PORT`, and `_APP_ENV` remain in plaintext because they have the `_` prefix

### YAML Format Example

The same secrets can be stored in YAML format:

```yaml
# secrets.eyaml
_public_key: 6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52
_private_key_enc: S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAA...
environment:
  DATABASE_PASSWORD: supersecretpassword
  API_KEY: sk-1234567890abcdef
  JWT_SECRET: my-jwt-signing-key
  _DATABASE_HOST: db.example.com
  _DATABASE_PORT: "5432"
  _APP_ENV: production
```

All commands work the same way with YAML files:

```shell
$ ejsonkms encrypt secrets.eyaml
$ ejsonkms decrypt secrets.eyaml
$ ejsonkms env secrets.eyaml
```

### TOML Format Example

To generate a TOML file, use a `.etoml` or `.toml` extension:

```shell
$ ejsonkms keygen --aws-region us-east-1 --kms-key-id bc436485-5092-42b8-92a3-0aa8b93536dc -o secrets.etoml
$ cat secrets.etoml
_public_key = "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52"
_private_key_enc = "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAA..."
```

The same secrets can be stored in TOML format:

```toml
# secrets.etoml
_public_key = "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52"
_private_key_enc = "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAA..."

[environment]
DATABASE_PASSWORD = "supersecretpassword"
API_KEY = "sk-1234567890abcdef"
JWT_SECRET = "my-jwt-signing-key"
_DATABASE_HOST = "db.example.com"
_DATABASE_PORT = "5432"
_APP_ENV = "production"
```

All commands work the same way with TOML files:

```shell
$ ejsonkms encrypt secrets.etoml
$ ejsonkms decrypt secrets.etoml
$ ejsonkms env secrets.etoml
```

Decrypting:

```shell
$ ejsonkms decrypt secrets.ejson
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q==",
  "environment": {
    "DATABASE_PASSWORD": "supersecretpassword",
    "API_KEY": "sk-1234567890abcdef",
    "JWT_SECRET": "my-jwt-signing-key",
    "_DATABASE_HOST": "db.example.com",
    "_DATABASE_PORT": "5432",
    "_APP_ENV": "production"
  }
}
```

Exporting shell variables:

```shell
$ exports=$(ejsonkms env secrets.ejson)
$ echo $exports
export DATABASE_PASSWORD='supersecretpassword'
export API_KEY='sk-1234567890abcdef'
export JWT_SECRET='my-jwt-signing-key'
export DATABASE_HOST='db.example.com'
export DATABASE_PORT='5432'
export APP_ENV='production'
$ eval $exports
$ echo $DATABASE_PASSWORD
supersecretpassword
```

Note that only values under the `environment` key will be exported using the `env` command.

When exporting keys prefixed with `_`, the first leading underscore is automatically stripped from variable names.
This means non-secret configuration values like `_DATABASE_HOST` will be exported as `DATABASE_HOST` without the underscore prefix. Keys with multiple underscores (e.g., `__KEY`) will have only the first underscore removed (becoming `_KEY`).

### Options

| Option | Description |
|--------|-------------|
| `-q`, `--quiet` | Suppress the `export` prefix (output: `KEY='value'`) |
| `--aws-region` | AWS Region |


## pre-commit hook

A [pre-commit](https://pre-commit.com/) hook is also supported to automatically run `ejsonkms encrypt` on all `.ejson`, `.eyaml`, `.eyml`, `.etoml`, and `.toml` files in a repository.

To use, add the following to a `.pre-commit-config.yaml` file in your repository:

```yaml
repos:
  - repo: https://github.com/runlevel5/ejsonkms-rs
    hooks:
      - id: run-ejsonkms-encrypt
```
