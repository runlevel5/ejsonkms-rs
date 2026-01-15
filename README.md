# ejsonkms-rs

A Rust implementation of [envato/ejsonkms](https://github.com/envato/ejsonkms). This is a drop-in replacement for the original Go implementation, with plan to support for **YAML** and **TOML** file formats.

 `ejsonkms` combines the [ejson](https://github.com/runlevel5/ejson-rs) and [ejson2env](https://github.com/runlevel5/ejson2env-rs) libraries with [AWS Key Management Service](https://aws.amazon.com/kms/) to simplify deployments on AWS. The EJSON private key is encrypted with KMS and stored inside the EJSON file as `_private_key_enc`. Access to decrypt secrets can be controlled with IAM permissions on the KMS key.

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
Private Key: ae5969d1fb70faab76198ee554bf91d2fffc44d027ea3d804a7c7f92876d518b
$ cat secrets.ejson
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q=="
}
```

Encrypting:

```
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

Exporting shell variables (from [ejson2env](https://github.com/Shopify/ejson2env)):

```shell
$ exports=$(ejsonkms env secrets.ejson)
$ echo $exports
export DATABASE_PASSWORD=supersecretpassword
export API_KEY=sk-1234567890abcdef
export JWT_SECRET=my-jwt-signing-key
export DATABASE_HOST=db.example.com
export DATABASE_PORT=5432
export APP_ENV=production
$ eval $exports
$ echo $DATABASE_PASSWORD
supersecretpassword
```

Note that only values under the `environment` key will be exported using the `env` command. The underscore prefix (`_`) is stripped from non-secret keys when exporting (e.g., `_DATABASE_HOST` becomes `DATABASE_HOST`).

## pre-commit hook

A [pre-commit](https://pre-commit.com/) hook is also supported to automatically run `ejsonkms encrypt` on all `.ejson` files in a repository.

To use, add the following to a `.pre-commit-config.yaml` file in your repository:

```yaml
repos:
  - repo: https://github.com/runlevel5/ejsonkms
    hooks:
      - id: run-ejsonkms-encrypt
```
