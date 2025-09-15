mod api;
mod cli;
mod config;
mod folder;
mod group;
mod keepass;
mod resource;
mod user;
mod util;

use std::collections::HashMap;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use clap_complete::generate;

use cli::root::{
    Cli, Commands, CreateEntity, DeleteEntity, GetEntity, ListEntity, MoveEntity, ShareEntity,
    UpdateEntity,
};
use config::Config;
use util::{output, session};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config and apply CLI overrides
    let mut cfg = Config::load().unwrap_or_default();
    apply_cli_overrides(&cli, &mut cfg)?;

    if cli.debug {
        eprintln!("[debug] server: {}", cfg.server_address);
    }

    match &cli.command {
        // ── Configure ──────────────────────────────────────────────────────
        Commands::Configure(args) => {
            cli::configure::run(args).await?;
        }

        // ── Verify ─────────────────────────────────────────────────────────
        Commands::Verify(args) => {
            cli::verify::run(args, &mut cfg).await?;
        }

        // ── Shell completions ──────────────────────────────────────────────
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(*shell, &mut cmd, name, &mut std::io::stdout());
        }

        // ── Documentation generation ───────────────────────────────────────
        Commands::Gendoc(args) => {
            cli::gendoc::run_gendoc(args)?;
        }

        // All other commands require a connected client
        cmd => {
            let client = session::get_client(&cfg).await?;
            let result = dispatch(cmd, &client, cli.json, cfg.workers).await;
            client.logout().await;
            result?;
        }
    }

    Ok(())
}

/// Apply CLI flag overrides on top of loaded config.
fn apply_cli_overrides(cli: &Cli, cfg: &mut Config) -> Result<()> {
    if let Some(v) = &cli.server_address {
        cfg.server_address = v.clone();
    }
    if let Some(v) = &cli.user_private_key {
        cfg.user_private_key = v.clone();
    }
    if let Some(v) = &cli.user_private_key_file {
        cfg.user_private_key_file = v.clone();
    }
    if let Some(v) = &cli.user_password {
        cfg.user_password = v.clone();
    }
    if let Some(v) = &cli.mfa_mode {
        cfg.mfa_mode = v.clone();
    }
    if let Some(v) = &cli.mfa_totp_token {
        cfg.mfa_totp_token = v.clone();
    }
    if let Some(v) = cli.mfa_totp_offset {
        cfg.mfa_totp_offset = v;
    }
    if let Some(v) = cli.mfa_retrys {
        cfg.mfa_retrys = v;
    }
    if let Some(v) = &cli.mfa_delay {
        cfg.mfa_delay = v.clone();
    }
    if cli.tls_skip_verify {
        cfg.tls_skip_verify = true;
    }
    if let Some(v) = &cli.tls_client_cert {
        cfg.tls_client_cert = v.clone();
    }
    if let Some(v) = &cli.tls_client_private_key {
        cfg.tls_client_private_key = v.clone();
    }
    if let Some(path) = &cli.tls_client_cert_file {
        cfg.tls_client_cert = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client cert file: {path}"))?;
    }
    if let Some(path) = &cli.tls_client_private_key_file {
        cfg.tls_client_private_key = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client private key file: {path}"))?;
    }
    if let Some(v) = &cli.proxy {
        cfg.proxy = v.clone();
    }
    if let Some(v) = &cli.timeout {
        cfg.timeout = v.clone();
    }
    if let Some(v) = cli.workers {
        if v > 0 {
            cfg.workers = v;
        }
    }
    if cli.debug {
        cfg.debug = true;
    }
    Ok(())
}

fn parse_filters(exprs: &[String]) -> Result<Vec<util::filter::Filter>> {
    exprs
        .iter()
        .map(|f| util::filter::Filter::parse(f))
        .collect()
}

fn parse_expiry_opt(s: &Option<String>) -> Result<Option<serde_json::Value>> {
    s.as_deref().map(resource::expiry::parse_expiry).transpose()
}

async fn dispatch(
    cmd: &Commands,
    client: &api::PassboltClient,
    json_output: bool,
    workers: usize,
) -> Result<()> {
    match cmd {
        // ── Create ──────────────────────────────────────────────────────────
        Commands::Create(args) => match &args.entity {
            CreateEntity::Resource {
                name,
                username,
                uri,
                password,
                description,
                folder_parent_id,
                expiry,
                totp_key,
                totp_algo,
                totp_digits,
                totp_period,
                totp_issuer,
            } => {
                use secrecy::ExposeSecret;
                use util::password::read_password;

                // Build TOTP data if a key was provided
                let totp = totp_key.as_ref().map(|key| api::types::TotpData {
                    secret_key: Some(key.clone()),
                    algorithm: totp_algo.clone(),
                    digits: *totp_digits,
                    period: *totp_period,
                    issuer: totp_issuer.clone(),
                });

                // Password is optional when TOTP-only; prompt only when no TOTP and no password
                let pwd: Option<String> = if let Some(p) = password {
                    Some(p.clone())
                } else if totp.is_none() {
                    let s = read_password("Password: ")?;
                    Some(s.expose_secret().to_string())
                } else {
                    None
                };

                let expiry_val = parse_expiry_opt(expiry)?;

                let res = resource::create::create_resource(
                    client,
                    name,
                    username.as_deref(),
                    uri.as_deref(),
                    description.as_deref(),
                    pwd.as_deref(),
                    folder_parent_id.as_deref(),
                    expiry_val,
                    totp,
                )
                .await?;

                if json_output {
                    output::print_json(&res)?;
                } else {
                    println!("Created resource: {} ({})", res.name, res.id);
                }
            }

            CreateEntity::Folder {
                name,
                folder_parent_id,
            } => {
                let folder =
                    folder::create::create_folder(client, name, folder_parent_id.as_deref())
                        .await?;
                if json_output {
                    output::print_json(&folder)?;
                } else {
                    println!("Created folder: {} ({})", folder.name, folder.id);
                }
            }

            CreateEntity::User {
                username,
                firstname,
                lastname,
                role,
            } => {
                let user =
                    user::create::create_user(client, username, firstname, lastname, role).await?;
                if json_output {
                    output::print_json(&user)?;
                } else {
                    println!(
                        "Created user: {} ({})",
                        user.username.as_deref().unwrap_or(""),
                        user.id
                    );
                }
            }

            CreateEntity::Group {
                name,
                user,
                manager,
            } => {
                if manager.is_empty() {
                    anyhow::bail!("At least one --manager is required");
                }
                let group = group::create::create_group(client, name, user, manager).await?;
                if json_output {
                    output::print_json(&group)?;
                } else {
                    println!("Created group: {} ({})", group.name, group.id);
                }
            }
        },

        // ── Get ─────────────────────────────────────────────────────────────
        Commands::Get(args) => match &args.entity {
            GetEntity::Resource { id } => {
                let res = resource::get::get_resource(client, id).await?;
                let secret = resource::get::get_resource_secret(client, &res).await?;

                // Decrypt v5 metadata when present; fall back to cleartext on error.
                let meta = if res.is_v5() {
                    match client.decrypt_resource_metadata(&res).await {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("[warn] Cannot decrypt metadata for '{}': {e}", res.id);
                            None
                        }
                    }
                } else {
                    None
                };

                let name = meta
                    .as_ref()
                    .and_then(|m| m.name.as_deref())
                    .unwrap_or(&res.name);
                let username = meta
                    .as_ref()
                    .and_then(|m| m.username.as_deref())
                    .unwrap_or_else(|| res.username.as_deref().unwrap_or(""));
                let uri = meta
                    .as_ref()
                    .and_then(|m| m.uris.as_ref()?.first()?.uri.as_deref())
                    .unwrap_or_else(|| res.uri.as_deref().unwrap_or(""));
                let description = meta
                    .as_ref()
                    .and_then(|m| m.description.as_deref())
                    .unwrap_or_else(|| secret.description.as_deref().unwrap_or(""));

                if json_output {
                    let mut v = serde_json::to_value(&res)?;
                    v["password"] =
                        serde_json::Value::String(secret.password.clone().unwrap_or_default());
                    if meta.is_some() {
                        v["name"] = serde_json::json!(name);
                        v["username"] = serde_json::json!(username);
                        v["uri"] = serde_json::json!(uri);
                        v["description"] = serde_json::json!(description);
                    }
                    output::print_json(&v)?;
                } else {
                    let expiry = res.expired.map(|d| d.to_rfc3339()).unwrap_or_default();
                    output::print_kv(&[
                        ("ID", res.id.as_str()),
                        ("Name", name),
                        ("Username", username),
                        ("URI", uri),
                        (
                            "Password",
                            secret.password.as_deref().unwrap_or("[encrypted]"),
                        ),
                        ("Description", description),
                        ("Expiry", expiry.as_str()),
                    ]);
                }
            }

            GetEntity::ResourcePermissions { id, .. } => {
                let perms = resource::get::get_resource_permissions(client, id).await?;
                if json_output {
                    output::print_json(&perms)?;
                } else {
                    let rows: Vec<Vec<String>> = perms
                        .iter()
                        .map(|p| {
                            vec![
                                p.aro.clone().unwrap_or_default(),
                                p.aro_foreign_key.clone().unwrap_or_default(),
                                p.type_name().to_string(),
                            ]
                        })
                        .collect();
                    output::print_table(&["ARO", "ARO ID", "Type"], rows);
                }
            }

            GetEntity::Folder { id } => {
                let folder = client.get_folder(id).await?;
                if json_output {
                    output::print_json(&folder)?;
                } else {
                    output::print_kv(&[
                        ("ID", &folder.id),
                        ("Name", &folder.name),
                        (
                            "Parent",
                            folder.folder_parent_id.as_deref().unwrap_or("(root)"),
                        ),
                    ]);
                }
            }

            GetEntity::FolderPermissions { id, .. } => {
                let perms = client.get_folder_permissions(id).await?;
                if json_output {
                    output::print_json(&perms)?;
                } else {
                    let rows: Vec<Vec<String>> = perms
                        .iter()
                        .map(|p| {
                            vec![
                                p.aro.clone().unwrap_or_default(),
                                p.aro_foreign_key.clone().unwrap_or_default(),
                                p.type_name().to_string(),
                            ]
                        })
                        .collect();
                    output::print_table(&["ARO", "ARO ID", "Type"], rows);
                }
            }

            GetEntity::User { id } => {
                let user = client.get_user(id).await?;
                if json_output {
                    output::print_json(&user)?;
                } else {
                    output::print_kv(&[
                        ("ID", &user.id),
                        ("Username", user.username.as_deref().unwrap_or("")),
                        ("First Name", user.first_name()),
                        ("Last Name", user.last_name()),
                        ("Role", user.role_name()),
                    ]);
                }
            }

            GetEntity::Group { id, .. } => {
                let group = client.get_group(id).await?;
                if json_output {
                    output::print_json(&group)?;
                } else {
                    output::print_kv(&[("ID", &group.id), ("Name", &group.name)]);
                    let rows: Vec<Vec<String>> = group
                        .groups_users
                        .iter()
                        .map(|gu| {
                            vec![
                                gu.user_id.clone().unwrap_or_default(),
                                if gu.is_admin.unwrap_or(false) {
                                    "Manager".into()
                                } else {
                                    "Member".into()
                                },
                            ]
                        })
                        .collect();
                    output::print_table(&["User ID", "Role"], rows);
                }
            }

            GetEntity::Totp { id } => {
                let (code, ttl) = resource::get::get_totp_code(client, id).await?;
                if json_output {
                    output::print_json(&serde_json::json!({ "code": code, "ttl": ttl }))?;
                } else {
                    println!("{code}  ({ttl}s remaining)");
                }
            }
        },

        // ── List ────────────────────────────────────────────────────────────
        Commands::List(args) => match &args.entity {
            ListEntity::Resource {
                favorite,
                own,
                group,
                folder,
                search,
                column,
                filter,
            } => {
                let filters = parse_filters(filter)?;

                let resources = resource::list::list_resources(
                    client,
                    *favorite,
                    *own,
                    group.clone(),
                    folder.clone(),
                    search.clone(),
                    &filters,
                )
                .await?;

                if json_output {
                    output::print_json_with_columns(&resources, column)?;
                } else {
                    // Default columns when none specified
                    let default_cols = ["ID", "FolderParentID", "Name", "Username", "URI"];
                    let effective_cols: Vec<String> = if column.is_empty() {
                        default_cols.iter().map(|s| s.to_string()).collect()
                    } else {
                        column.clone()
                    };

                    // Auto-decrypt when Password or Description columns are requested
                    let needs_decrypt = effective_cols
                        .iter()
                        .any(|c| matches!(c.to_lowercase().as_str(), "password" | "description"));

                    let secrets = if needs_decrypt {
                        client.decrypt_secrets_batch(&resources, workers).await?
                    } else {
                        HashMap::new()
                    };

                    let metadatas = client.decrypt_metadata_batch(&resources).await;

                    let rows: Vec<Vec<String>> = resources
                        .iter()
                        .map(|r| {
                            let secret = secrets.get(&r.id);
                            let meta = metadatas.get(&r.id);
                            effective_cols
                                .iter()
                                .map(|c| match c.to_lowercase().as_str() {
                                    "id" => r.id.clone(),
                                    "name" => meta
                                        .and_then(|m| m.name.as_deref())
                                        .unwrap_or(&r.name)
                                        .to_string(),
                                    "username" => meta
                                        .and_then(|m| m.username.as_deref())
                                        .unwrap_or_else(|| r.username.as_deref().unwrap_or(""))
                                        .to_string(),
                                    "uri" => meta
                                        .and_then(|m| m.uris.as_ref()?.first()?.uri.as_deref())
                                        .unwrap_or_else(|| r.uri.as_deref().unwrap_or(""))
                                        .to_string(),
                                    "folderparentid" | "folder_parent_id" => {
                                        r.folder_parent_id.clone().unwrap_or_default()
                                    }
                                    "password" => secret
                                        .and_then(|s| s.password.as_deref())
                                        .unwrap_or("")
                                        .to_string(),
                                    "description" => meta
                                        .and_then(|m| m.description.as_deref())
                                        .or_else(|| secret.and_then(|s| s.description.as_deref()))
                                        .unwrap_or("")
                                        .to_string(),
                                    "created" => {
                                        r.created.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    "modified" => {
                                        r.modified.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    "expired" | "expiry" => {
                                        r.expired.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    _ => String::new(),
                                })
                                .collect()
                        })
                        .collect();

                    let headers: Vec<&str> = effective_cols.iter().map(String::as_str).collect();
                    output::print_table(&headers, rows);
                }
            }

            ListEntity::Folder {
                search,
                folder,
                group,
                column,
                filter,
            } => {
                let filters = parse_filters(filter)?;

                let folders = folder::list::list_folders(
                    client,
                    search.clone(),
                    group.clone(),
                    folder.clone(),
                    &filters,
                )
                .await?;

                if json_output {
                    output::print_json_with_columns(&folders, column)?;
                } else {
                    let default_cols = ["ID", "Name", "Parent ID"];
                    let effective_cols: Vec<String> = if column.is_empty() {
                        default_cols.iter().map(|s| s.to_string()).collect()
                    } else {
                        column.clone()
                    };
                    let rows: Vec<Vec<String>> = folders
                        .iter()
                        .map(|f| {
                            effective_cols
                                .iter()
                                .map(|c| match c.to_lowercase().as_str() {
                                    "id" => f.id.clone(),
                                    "name" => f.name.clone(),
                                    "parent id" | "folderparentid" | "folder_parent_id" => {
                                        f.folder_parent_id.clone().unwrap_or_default()
                                    }
                                    "created" => {
                                        f.created.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    "modified" => {
                                        f.modified.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    _ => String::new(),
                                })
                                .collect()
                        })
                        .collect();
                    let headers: Vec<&str> = effective_cols.iter().map(String::as_str).collect();
                    output::print_table(&headers, rows);
                }
            }

            ListEntity::User {
                group,
                resource,
                search,
                admin,
                column,
                filter,
            } => {
                let filters = parse_filters(filter)?;

                let users = user::list::list_users(
                    client,
                    search.clone(),
                    group.clone(),
                    resource.clone(),
                    *admin,
                    &filters,
                )
                .await?;

                if json_output {
                    output::print_json_with_columns(&users, column)?;
                } else {
                    let default_cols = ["ID", "Username", "First Name", "Last Name", "Role"];
                    let effective_cols: Vec<String> = if column.is_empty() {
                        default_cols.iter().map(|s| s.to_string()).collect()
                    } else {
                        column.clone()
                    };
                    let rows: Vec<Vec<String>> = users
                        .iter()
                        .map(|u| {
                            effective_cols
                                .iter()
                                .map(|c| match c.to_lowercase().as_str() {
                                    "id" => u.id.clone(),
                                    "username" => u.username.clone().unwrap_or_default(),
                                    "first name" | "firstname" | "first_name" => {
                                        u.first_name().to_string()
                                    }
                                    "last name" | "lastname" | "last_name" => {
                                        u.last_name().to_string()
                                    }
                                    "role" => u.role_name().to_string(),
                                    "created" => {
                                        u.created.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    "modified" => {
                                        u.modified.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    _ => String::new(),
                                })
                                .collect()
                        })
                        .collect();
                    let headers: Vec<&str> = effective_cols.iter().map(String::as_str).collect();
                    output::print_table(&headers, rows);
                }
            }

            ListEntity::Group {
                user,
                manager,
                column,
                filter,
            } => {
                let filters = parse_filters(filter)?;

                let groups =
                    group::list::list_groups(client, user.clone(), manager.clone(), &filters)
                        .await?;

                if json_output {
                    output::print_json_with_columns(&groups, column)?;
                } else {
                    let default_cols = ["ID", "Name", "Members"];
                    let effective_cols: Vec<String> = if column.is_empty() {
                        default_cols.iter().map(|s| s.to_string()).collect()
                    } else {
                        column.clone()
                    };
                    let rows: Vec<Vec<String>> = groups
                        .iter()
                        .map(|g| {
                            effective_cols
                                .iter()
                                .map(|c| match c.to_lowercase().as_str() {
                                    "id" => g.id.clone(),
                                    "name" => g.name.clone(),
                                    "members" => g.groups_users.len().to_string(),
                                    "created" => {
                                        g.created.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    "modified" => {
                                        g.modified.map(|d| d.to_rfc3339()).unwrap_or_default()
                                    }
                                    _ => String::new(),
                                })
                                .collect()
                        })
                        .collect();
                    let headers: Vec<&str> = effective_cols.iter().map(String::as_str).collect();
                    output::print_table(&headers, rows);
                }
            }
        },

        // ── Update ──────────────────────────────────────────────────────────
        Commands::Update(args) => match &args.entity {
            UpdateEntity::Resource {
                id,
                name,
                username,
                uri,
                password,
                description,
                expiry,
                totp_key,
                totp_algo,
                totp_digits,
                totp_period,
                totp_issuer,
                remove_totp,
            } => {
                let expiry_val = parse_expiry_opt(expiry)?;

                let res = resource::update::update_resource(
                    client,
                    id,
                    name.as_deref(),
                    username.as_deref(),
                    uri.as_deref(),
                    description.as_deref(),
                    password.as_deref(),
                    expiry_val,
                    totp_key.as_deref(),
                    totp_algo.as_deref(),
                    *totp_digits,
                    *totp_period,
                    totp_issuer.as_deref(),
                    *remove_totp,
                )
                .await?;

                if json_output {
                    output::print_json(&res)?;
                } else {
                    println!("Updated resource: {} ({})", res.name, res.id);
                }
            }

            UpdateEntity::Folder { id, name } => {
                let payload = api::types::UpdateFolderPayload { name: name.clone() };
                let folder = client.update_folder(id, &payload).await?;
                if json_output {
                    output::print_json(&folder)?;
                } else {
                    println!("Updated folder: {} ({})", folder.name, folder.id);
                }
            }

            UpdateEntity::User {
                id,
                firstname,
                lastname,
                role,
            } => {
                let user = user::update::update_user(
                    client,
                    id,
                    firstname.as_deref(),
                    lastname.as_deref(),
                    role.as_deref(),
                )
                .await?;
                if json_output {
                    output::print_json(&user)?;
                } else {
                    println!("Updated user: {}", user.id);
                }
            }

            UpdateEntity::Group {
                id,
                name,
                user,
                manager,
                delete,
            } => {
                let group =
                    group::update::update_group(client, id, name.as_deref(), user, manager, delete)
                        .await?;
                if json_output {
                    output::print_json(&group)?;
                } else {
                    println!("Updated group: {} ({})", group.name, group.id);
                }
            }
        },

        // ── Delete ──────────────────────────────────────────────────────────
        Commands::Delete(args) => match &args.entity {
            DeleteEntity::Resource { id } => {
                client.delete_resource(id).await?;
                println!("Deleted resource {id}");
            }
            DeleteEntity::Folder { id } => {
                client.delete_folder(id).await?;
                println!("Deleted folder {id}");
            }
            DeleteEntity::User { id } => {
                client.delete_user(id).await?;
                println!("Deleted user {id}");
            }
            DeleteEntity::Group { id } => {
                client.delete_group(id).await?;
                println!("Deleted group {id}");
            }
        },

        // ── Share ───────────────────────────────────────────────────────────
        Commands::Share(args) => match &args.entity {
            ShareEntity::Resource {
                id,
                r#type,
                user,
                group,
            } => {
                resource::share::share_resource(client, id, user, group, *r#type).await?;
                println!("Shared resource {id}");
            }
            ShareEntity::Folder {
                id,
                r#type,
                user,
                group,
            } => {
                folder::share::share_folder(client, id, user, group, *r#type).await?;
                println!("Shared folder {id}");
            }
        },

        // ── Move ────────────────────────────────────────────────────────────
        Commands::Move(args) => match &args.entity {
            MoveEntity::Resource {
                id,
                folder_parent_id,
            } => {
                client
                    .move_resource(id, folder_parent_id.as_deref())
                    .await?;
                println!("Moved resource {id}");
            }
            MoveEntity::Folder {
                id,
                folder_parent_id,
            } => {
                client.move_folder(id, folder_parent_id.as_deref()).await?;
                println!("Moved folder {id}");
            }
        },

        // ── Exec ────────────────────────────────────────────────────────────
        Commands::Exec(args) => {
            cli::exec::run(args, client).await?;
        }

        // ── Export ──────────────────────────────────────────────────────────
        Commands::Export(args) => {
            cli::export::run(args, client, workers).await?;
        }

        Commands::Configure(_)
        | Commands::Verify(_)
        | Commands::Completion { .. }
        | Commands::Gendoc(_) => {
            unreachable!("handled above")
        }
    }

    Ok(())
}
