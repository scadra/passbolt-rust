---
paths:
  - "crates/**/*.rs"
---

# Rust

- Names are full words that say what the value is: `query`, `state`, `response`, `permission`, not `q`, `st`, `resp`, `p`, `x`, `tmp`, `data2`. Applies to closure parameters too.
- Match the surrounding style; no comments that paraphrase code, no decorative banners in new code.
- SDK returns `PassboltError`; `anyhow` only in the CLI.
- No panics on input: `try_*`/`checked_*`, no `unwrap` outside tests.
- Serde field names follow the Passbolt API (`gpgkey`, `groups_users`…); check go-passbolt when unsure.
- Before done: `cargo fmt --all`, `cargo clippy --workspace --all-targets` (no new warnings), `cargo test --workspace`, `bash scripts/license-headers.sh`.
