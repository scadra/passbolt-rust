
	      ____                  __          ____
	     / __ \____  _____ ____/ /_  ____  / / /_
	    / /_/ / __ `/ ___/ ___/ __ \/ __ \/ / __/
	   / ____/ /_/ (__  |__  ) /_/ / /_/ / / /_
	  /_/    \__,_/____/____/_.___/\____/_/\__/

	Open source password manager for teams
	(c) 2025 Passbolt SA
	https://www.passbolt.com

## License

Passbolt - Open source password manager for teams

(c) 2025 Passbolt SA

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
Public License (AGPL) as published by the Free Software Foundation version 3.

The name "Passbolt" is a registered trademark of Passbolt SA, and Passbolt SA hereby declines to grant a trademark
license to "Passbolt" pursuant to the GNU Affero General Public License version 3 Section 7(e), without a separate
agreement with Passbolt SA.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not,
see [GNU Affero General Public License v3](http://www.gnu.org/licenses/agpl-3.0.html).

## About passbolt

Passbolt is an open source password manager for teams. It allows to securely share and store credentials.
For instance, the wifi password of your office, or the administrator password of a router, or your organisation social
media account password, all of them can be secured using Passbolt.

You can try a demo of passbolt at [https://demo.passbolt.com](https://demo.passbolt.com).

## About passbolt-rs

A fast, secure CLI and SDK for [Passbolt](https://www.passbolt.com/) — written in Rust.

Full alternative to [go-passbolt-cli](https://github.com/passbolt/go-passbolt-cli) with no OpenSSL dependency (pure Rust TLS + GPG).
The workspace also ships the `passbolt-sdk` library and its WASM and FFI bindings (see [docs/sdk-specs](docs/sdk-specs/README.md)).

> Known gaps with go-passbolt / go-passbolt-cli are tracked in [docs/PARITY-GO.md](docs/PARITY-GO.md).

# Contributing

Please check [CONTRIBUTING.md](CONTRIBUTING.md) for more information about how to get involved.

## Reporting a security Issue

If you've found a security related issue in Passbolt, please don't open an issue on GitHub. Follow our responsible disclosure process: https://www.passbolt.com/docs/contribute/security/vulnerability/.

# Quick how-to

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Commands](#commands)
  - [configure](#configure)
  - [verify](#verify)
  - [completion](#completion)
  - [resource](#resource)
  - [folder](#folder)
  - [user](#user)
  - [group](#group)
  - [exec](#exec)
  - [export](#export)
- [Global Flags](#global-flags)
- [Output Formats](#output-formats)
- [Filter Syntax](#filter-syntax)
- [Expiry Format](#expiry-format)
- [MFA](#mfa)
- [TLS / mTLS](#tls--mtls)

---

## Installation

```bash
git clone https://github.com/scadra/passbolt-rust.git
cd passbolt-rust
cargo build --release
# binary at target/release/passbolt
sudo cp target/release/passbolt /usr/local/bin/
```

**Requirements:** Rust 1.87+ (no OpenSSL required — uses rustls).

---

## Quick Start

```bash
# 1. Configure credentials
passbolt configure \
  --server-address https://passbolt.example.com \
  --user-private-key-file ~/.gnupg/private.asc \
  --user-password "my-gpg-passphrase"

# 2. Verify server identity (optional but recommended)
passbolt verify

# 3. List all passwords
passbolt list resource

# 4. Get a specific password (decrypted)
passbolt get resource --id <UUID>

# 5. Create a new entry
passbolt create resource --name "GitHub" --username "john" --uri https://github.com
```

---

## Configuration

Config file location: `~/.config/passbolt/config.toml`

```toml
server_address         = "https://passbolt.example.com"

# PGP private key — inline or file path (choose one)
user_private_key       = """-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----"""
# user_private_key_file = "/home/user/.gnupg/private.asc"

user_password          = "my-gpg-passphrase"

# MFA (optional)
mfa_mode               = "interactive-totp"   # or "non-interactive-totp" / "none"
mfa_totp_token         = ""                   # TOTP secret (for non-interactive)
mfa_totp_offset        = 0                    # clock skew in seconds
mfa_retrys             = 3
mfa_delay              = "10s"

# TLS
tls_skip_verify        = false
# tls_client_cert_file      = "/path/to/cert.pem"
# tls_client_private_key_file = "/path/to/key.pem"

# Performance
timeout                = "1m"
workers                = 0    # 0 = auto (number of CPU cores)

# Debug
debug                  = false
```

### Priority Order

CLI flags > Environment variables (`PASSBOLT_*`) > Config file > Defaults

---

## Authentication

The CLI uses a **2-step GPG challenge-response** flow to obtain a JWT:

1. `POST /auth/jwt/login.json` with the user's key fingerprint
2. Server responds with a GPG-encrypted challenge
3. CLI decrypts the challenge with the user's private key + passphrase
4. `POST /auth/jwt/login.json` with the decrypted token
5. Server returns `access_token` + `refresh_token` (JWT)

The `verify` command pre-validates the server's identity and caches verification tokens.

---

## Commands

### configure

Save credentials to the config file.

```bash
passbolt configure [OPTIONS]
```

| Option | Description |
|---|---|
| `--server-address` | Passbolt server URL |
| `--user-private-key` | PGP private key (armored, inline) |
| `--user-private-key-file` | Path to PGP private key file |
| `--user-password` | GPG passphrase |
| `--mfa-mode` | `interactive-totp` \| `non-interactive-totp` \| `none` |
| `--mfa-totp-token` | TOTP secret (for non-interactive mode) |
| `--tls-skip-verify` | Skip TLS verification (insecure) |
| `--timeout` | Request timeout (e.g. `30s`, `1m`) |
| `--workers` | Parallel workers (0 = auto) |

---

### verify

Verify server identity and cache tokens.

```bash
passbolt verify
```

---

### completion

Generate shell completion scripts.

```bash
passbolt completion bash   >> ~/.bashrc
passbolt completion zsh    >> ~/.zshrc
passbolt completion fish   > ~/.config/fish/completions/passbolt.fish
passbolt completion powershell
```

---

### resource

#### list resource

```bash
passbolt list resource [OPTIONS]
```

| Option | Description |
|---|---|
| `--favorite` | Only show favorited entries |
| `--own` | Only show entries owned by the current user |
| `-g, --group <UUID>` | Filter by group |
| `-f, --folder <UUID>` | Filter by folder |
| `-c, --column <COL>` | Columns to display (repeatable): `ID`, `Name`, `Username`, `URI` |
| `--filter <EXPR>` | Field filter expression (repeatable, see [Filter Syntax](#filter-syntax)) |

```bash
# Examples
passbolt list resource
passbolt list resource --own -c Name -c Username -c URI
passbolt list resource --filter "name~=github" --json
passbolt list resource --folder <FOLDER_UUID> --filter "username!=admin"
```

#### get resource

Retrieve a resource with its **decrypted** password.

```bash
passbolt get resource --id <UUID>
passbolt get resource --id <UUID> --json
```

#### get resource-permissions

List who has access to a resource.

```bash
passbolt get resource-permissions --id <UUID>
passbolt get resource-permissions --id <UUID> -c ARO -c "Permission Type"
```

#### create resource

```bash
passbolt create resource --name <NAME> [OPTIONS]
```

| Option | Description |
|---|---|
| `-n, --name <NAME>` | Entry name **(required)** |
| `-u, --username <USERNAME>` | Username |
| `--uri <URI>` | URL |
| `-p, --password <PASSWORD>` | Password (prompted securely if omitted) |
| `-d, --description <DESC>` | Description |
| `-f, --folder-parent-id <UUID>` | Parent folder |
| `--expiry <EXPIRY>` | Expiry date (see [Expiry Format](#expiry-format)) |

```bash
passbolt create resource \
  --name "AWS Console" \
  --username "john@example.com" \
  --uri https://console.aws.amazon.com \
  --folder-parent-id <FOLDER_UUID> \
  --expiry "90d"
```

#### update resource

```bash
passbolt update resource --id <UUID> [OPTIONS]
```

Options: `--name`, `--username`, `--uri`, `--password`, `--description`, `--expiry`

```bash
passbolt update resource --id <UUID> --password "newpassword" --expiry "30d"
```

#### delete resource

```bash
passbolt delete resource --id <UUID>
```

#### share resource

```bash
passbolt share resource --id <UUID> [OPTIONS]
```

| Option | Description |
|---|---|
| `-t, --type <TYPE>` | Permission: `1`=Read, `7`=Update, `15`=Owner (default: `1`) |
| `-u, --user <UUID>` | User to share with (repeatable) |
| `-g, --group <UUID>` | Group to share with (repeatable) |

```bash
passbolt share resource --id <UUID> \
  --type 7 \
  --user <USER_UUID> \
  --group <GROUP_UUID>
```

#### move resource

```bash
passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID>
# Move to root:
passbolt move resource --id <UUID>
```

---

### folder

#### list folder

```bash
passbolt list folder [OPTIONS]
```

Options: `-s/--search`, `-f/--folder` (parent), `-g/--group`, `-c/--column`, `--filter`

#### get folder

```bash
passbolt get folder --id <UUID>
```

#### get folder-permissions

```bash
passbolt get folder-permissions --id <UUID>
```

#### create folder

```bash
passbolt create folder --name "DevOps" --folder-parent-id <PARENT_UUID>
```

#### update folder

```bash
passbolt update folder --id <UUID> --name "New Name"
```

#### delete folder

```bash
passbolt delete folder --id <UUID>
```

#### share folder

```bash
passbolt share folder --id <UUID> --type 15 --user <UUID>
```

#### move folder

```bash
passbolt move folder --id <UUID> --folder-parent-id <TARGET_UUID>
```

---

### user

#### list user

```bash
passbolt list user [OPTIONS]
```

| Option | Description |
|---|---|
| `-g, --group <UUID>` | Filter by group membership |
| `-r, --resource <UUID>` | Filter by resource access |
| `-s, --search <TEXT>` | Search by name or email |
| `--admin` | Only show admins |
| `-c, --column <COL>` | Columns: `ID`, `Username`, `First Name`, `Last Name`, `Role` |

#### get user

```bash
passbolt get user --id <UUID>
```

#### create user

```bash
passbolt create user \
  --username alice@example.com \
  --firstname Alice \
  --lastname Martin \
  --role user       # or "admin"
```

#### update user

```bash
passbolt update user --id <UUID> --lastname "Dupont" --role admin
```

#### delete user

```bash
passbolt delete user --id <UUID>
```

---

### group

#### list group

```bash
passbolt list group [OPTIONS]
```

| Option | Description |
|---|---|
| `-u, --user <UUID>` | Filter by member user |
| `-m, --manager <UUID>` | Filter by manager |
| `-c, --column <COL>` | Columns: `ID`, `Name`, `Members` |

#### get group

```bash
passbolt get group --id <UUID>
```

#### create group

```bash
passbolt create group \
  --name "DevOps" \
  --manager <MANAGER_UUID> \
  --user <USER_UUID1> \
  --user <USER_UUID2>
```

At least one `--manager` is required.

#### update group

```bash
passbolt update group --id <UUID> \
  --name "New Name" \
  --user <NEW_MEMBER_UUID> \
  --manager <NEW_MANAGER_UUID> \
  --delete <REMOVED_USER_UUID>
```

#### delete group

```bash
passbolt delete group --id <UUID>
```

---

### exec

Execute a command with Passbolt secrets injected as environment variables.

Any environment variable containing a `passbolt://<UUID>` URI is replaced with the decrypted password before the subprocess starts.

```bash
export DB_PASSWORD="passbolt://a1b2c3d4-e5f6-7890-abcd-ef1234567890"

passbolt exec -- psql -U myuser -d mydb
passbolt exec -- mysql -u root -p"$DB_PASSWORD"
passbolt exec -- ansible-playbook site.yml
```

The subprocess inherits all environment variables; Passbolt URIs are resolved transparently.

---

### export

#### export keepass

Export all accessible resources to a KeePass `.kdbx` file (KDBX4 format, AES-256).

```bash
passbolt export keepass --output ~/backup.kdbx
# Master password is prompted interactively if not provided:
passbolt export keepass --output ~/backup.kdbx --password "kdbx-master-password"
```

Folder structure is preserved in KeePass groups.

---

## Global Flags

These flags apply to every command and can be set via CLI, env var, or config file.

| Flag | Env Variable | Default | Description |
|---|---|---|---|
| `--server-address` | `PASSBOLT_SERVER_ADDRESS` | — | Server URL |
| `--user-private-key` | `PASSBOLT_USER_PRIVATE_KEY` | — | PGP private key (inline) |
| `--user-private-key-file` | `PASSBOLT_USER_PRIVATE_KEY_FILE` | — | Path to PGP key file |
| `--user-password` | `PASSBOLT_USER_PASSWORD` | — | GPG passphrase |
| `--config` | `PASSBOLT_CONFIG` | `~/.config/passbolt/config.toml` | Config file path |
| `--mfa-mode` | `PASSBOLT_MFA_MODE` | `interactive-totp` | MFA mode |
| `--mfa-totp-token` | `PASSBOLT_MFA_TOTP_TOKEN` | — | TOTP secret |
| `--mfa-totp-offset` | `PASSBOLT_MFA_TOTP_OFFSET` | `0` | TOTP clock offset (seconds) |
| `--mfa-retrys` | `PASSBOLT_MFA_RETRYS` | `3` | MFA retry count |
| `--mfa-delay` | `PASSBOLT_MFA_DELAY` | `10s` | Delay between MFA retries |
| `--tls-skip-verify` | `PASSBOLT_TLS_SKIP_VERIFY` | `false` | Skip TLS verification |
| `--tls-client-cert` | `PASSBOLT_TLS_CLIENT_CERT` | — | mTLS client cert (inline) |
| `--tls-client-cert-file` | `PASSBOLT_TLS_CLIENT_CERT_FILE` | — | mTLS client cert file |
| `--tls-client-private-key` | `PASSBOLT_TLS_CLIENT_PRIVATE_KEY` | — | mTLS client key (inline) |
| `--tls-client-private-key-file` | `PASSBOLT_TLS_CLIENT_PRIVATE_KEY_FILE` | — | mTLS client key file |
| `--timeout` | `PASSBOLT_TIMEOUT` | `1m` | Request timeout |
| `--workers` | `PASSBOLT_WORKERS` | `0` (auto) | Parallel workers |
| `--debug` | `PASSBOLT_DEBUG` | `false` | Debug output |
| `-j, --json` | — | `false` | JSON output |

---

## Output Formats

**Table (default)**

```
┌──────────────────────────────────────┬────────────┬──────────────┐
│ ID                                   │ Name       │ Username     │
├──────────────────────────────────────┼────────────┼──────────────┤
│ a1b2c3d4-e5f6-7890-abcd-ef1234567890 │ GitHub     │ alice        │
│ b2c3d4e5-f6a7-8901-bcde-f12345678901 │ AWS        │ ops@corp.com │
└──────────────────────────────────────┴────────────┴──────────────┘
```

**JSON** (`--json`)

```bash
passbolt list resource --json | jq '.[].name'
```

```json
[
  {
    "id": "a1b2c3d4-...",
    "name": "GitHub",
    "username": "alice",
    "uri": "https://github.com"
  }
]
```

**Key-Value** (`get` commands without `--json`)

```
ID:         a1b2c3d4-e5f6-7890-abcd-ef1234567890
Name:       GitHub
Username:   alice
URI:        https://github.com
Password:   s3cr3t
```

---

## Filter Syntax

The `--filter` flag supports the following operators:

| Operator | Meaning | Example |
|---|---|---|
| `field=value` | Exact match (case-insensitive) | `--filter "role=admin"` |
| `field~=value` | Contains | `--filter "name~=github"` |
| `field^=value` | Starts with | `--filter "username^=john"` |
| `field$=value` | Ends with | `--filter "uri$=.com"` |
| `field!=value` | Not equal | `--filter "username!=admin"` |

Multiple `--filter` flags are ANDed together:

```bash
passbolt list resource \
  --filter "name~=prod" \
  --filter "username!=root"
```

---

## Expiry Format

Used with `create resource` and `update resource`:

| Value | Meaning |
|---|---|
| `"2025-12-31T00:00:00Z"` | Absolute date (RFC3339) |
| `"90d"` | 90 days from now |
| `"48h"` | 48 hours from now |
| `"30m"` | 30 minutes from now |
| `"none"` or `""` | Remove expiry |

```bash
passbolt create resource --name "Temp token" --expiry "7d"
passbolt update resource --id <UUID> --expiry "none"
```

---

## MFA

Three modes are supported:

**`interactive-totp`** (default) — prompts for a 6-digit TOTP code on login:
```
Enter TOTP code: ______
```

**`non-interactive-totp`** — provide the TOTP *secret* (not the 6-digit code) in config or env:
```bash
passbolt list resource \
  --mfa-mode non-interactive-totp \
  --mfa-totp-token "JBSWY3DPEBLW64TMMQ======"
```
The CLI computes the current code automatically. Use `--mfa-totp-offset` to compensate for clock drift.

**`none`** — disable MFA (for accounts without MFA configured).

---

## TLS / mTLS

Skip verification (self-signed certs, labs):
```bash
passbolt list resource --tls-skip-verify
```

Mutual TLS (client certificate authentication):
```bash
passbolt list resource \
  --tls-client-cert-file /etc/passbolt/client.crt \
  --tls-client-private-key-file /etc/passbolt/client.key
```

Or inline in config:
```toml
tls_client_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"""
tls_client_private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"""
```

---

## Security Notes

- No OpenSSL dependency — TLS via [rustls](https://github.com/rustls/rustls), GPG via [pgp](https://github.com/rpgp/rpgp) (pure Rust).
- All in-memory credentials use [`zeroize`](https://github.com/RustCrypto/utils/tree/master/zeroize): memory is wiped on drop.
- Passwords are stored as `secrecy::SecretString` — never logged, even in `--debug` mode.
- JWT tokens are zeroized after use.
- GPG decryption buffers are cleared after each operation.

---

## Development

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo fmt
bash scripts/license-headers.sh   # every .rs file must carry the Passbolt license header
```

Tests use `assert_cmd` + `mockito` for HTTP mocking. See `tests/` directory.

# Credits

https://www.passbolt.com/credits
