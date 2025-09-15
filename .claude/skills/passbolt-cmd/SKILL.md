---
name: passbolt-cmd
description: Generate a new Passbolt CLI subcommand following project patterns (clap derive, PassboltClient, anyhow, output formatter)
triggers: new command, add subcommand, create command, ajouter commande
layer: 3
domain: cli
---

When creating a new Passbolt CLI subcommand, always follow this pattern:

1. Add variant to `Commands` enum in `src/cli.rs` with clap derive
2. Create handler in `src/commands/<name>.rs`:
   - Takes `&PassboltClient` + command args
   - Returns `anyhow::Result<()>`
   - Calls `output::print_*()` for display
3. Register in `main.rs` match block
4. Add integration test in `tests/<name>.rs` with mockito

Example structure for a new `list-passwords` command:
- Clap: `List { #[arg(short, long)] folder: Option<String> }`
- Handler: `pub async fn run(client: &PassboltClient, folder: Option<String>) -> anyhow::Result<()>`
- Never expose raw secrets in output without --show-secret flag
