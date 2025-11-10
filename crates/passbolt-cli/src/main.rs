// Passbolt ~ Open source password manager for teams
// Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

mod cli;
mod config;
mod keepass;
mod util;

use std::collections::HashMap;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use passbolt_sdk::types::ResourceMetadata;

use cli::root::{
    Cli, Commands, CreateEntity, DeleteEntity, GetEntity, ListEntity, MoveEntity, ShareEntity,
    UpdateEntity,
};
use config::Config;
use util::{output, session};

/// Type alias for the concrete SDK client used by the CLI.
pub type Client = passbolt_sdk::PassboltSdk<passbolt_sdk::NativeHttpClient>;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(path) = &cli.config {
        Config::set_path(path.into());
    }

    match &cli.command {
        // ── Configure ──────────────────────────────────────────────────────
        Commands::Configure(args) => {
            cli::configure::run(args)?;
        }

        // ── Shell completions ──────────────────────────────────────────────
        Commands::Completion { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            generate(*shell, &mut command, name, &mut std::io::stdout());
        }

        // ── Documentation generation ───────────────────────────────────────
        Commands::Gendoc(args) => {
            cli::gendoc::run_gendoc(args)?;
        }

        // ── Verify ─────────────────────────────────────────────────────────
        Commands::Verify(args) => {
            let mut config = load_config(&cli)?;
            cli::verify::run(args, &mut config).await?;
        }

        // All other commands require a connected client
        command => {
            let config = load_config(&cli)?;
            let client = session::get_client(&config).await?;
            let result = dispatch(command, &client, cli.json, config.workers).await;
            client.logout().await;
            result?;
        }
    }

    Ok(())
}

/// Load the config file and environment, then apply the command-line flags over them.
fn load_config(cli: &Cli) -> Result<Config> {
    let mut config = Config::load()?;
    apply_cli_overrides(cli, &mut config)?;
    if cli.debug {
        eprintln!("[debug] server: {}", config.server_address);
    }
    Ok(config)
}

/// Apply CLI flag overrides on top of loaded config.
fn apply_cli_overrides(cli: &Cli, config: &mut Config) -> Result<()> {
    if let Some(value) = &cli.server_address {
        config.server_address.clone_from(value);
    }
    if let Some(value) = &cli.user_private_key {
        config.user_private_key.clone_from(value);
    }
    if let Some(value) = &cli.user_private_key_file {
        config.user_private_key_file.clone_from(value);
    }
    if let Some(value) = &cli.user_password {
        config.user_password.clone_from(value);
    }
    if let Some(value) = &cli.mfa_mode {
        config.mfa_mode.clone_from(value);
    }
    if let Some(value) = &cli.mfa_totp_token {
        config.mfa_totp_token.clone_from(value);
    }
    if let Some(value) = cli.mfa_totp_offset {
        config.mfa_totp_offset = value;
    }
    if let Some(value) = cli.mfa_retrys {
        config.mfa_retrys = value;
    }
    if let Some(value) = &cli.mfa_delay {
        config.mfa_delay.clone_from(value);
    }
    if cli.tls_skip_verify {
        config.tls_skip_verify = true;
    }
    if let Some(value) = &cli.tls_client_cert {
        config.tls_client_cert.clone_from(value);
    }
    if let Some(value) = &cli.tls_client_private_key {
        config.tls_client_private_key.clone_from(value);
    }
    if let Some(path) = &cli.tls_client_cert_file {
        config.tls_client_cert = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client cert file: {path}"))?;
    }
    if let Some(path) = &cli.tls_client_private_key_file {
        config.tls_client_private_key = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client private key file: {path}"))?;
    }
    if let Some(value) = &cli.proxy {
        config.proxy.clone_from(value);
    }
    if let Some(value) = &cli.resolve {
        config.resolve.clone_from(value);
    }
    if let Some(value) = &cli.timeout {
        config.timeout.clone_from(value);
    }
    if let Some(value) = cli.workers {
        config.workers = value;
    }
    if cli.debug {
        config.debug = true;
    }
    Ok(())
}

fn parse_filters(expressions: &[String]) -> Result<Vec<passbolt_sdk::filter::Filter>> {
    expressions
        .iter()
        .map(|expression| passbolt_sdk::filter::Filter::parse(expression))
        .collect()
}

fn parse_expiry_opt(expiry: Option<&String>) -> Result<Option<serde_json::Value>> {
    expiry
        .map(String::as_str)
        .map(passbolt_sdk::resource::expiry::parse_expiry)
        .transpose()
}

#[allow(clippy::too_many_lines)]
async fn dispatch(
    command: &Commands,
    client: &Client,
    json_output: bool,
    workers: usize,
) -> Result<()> {
    match command {
        // ── Create ──────────────────────────────────────────────────────────
        Commands::Create(args) => match &args.entity {
            CreateEntity::Resource {
                resource_type,
                name,
                username,
                uri,
                password,
                description,
                note,
                pin_code,
                folder_parent_id,
                expiry,
                totp_key,
                totp_algo,
                totp_digits,
                totp_period,
            } => {
                use passbolt_sdk::resource::create::NewResource;
                use secrecy::ExposeSecret;
                use util::password::read_password;

                let totp = totp_key.as_ref().map(|key| passbolt_sdk::types::TotpData {
                    secret_key: Some(key.clone()),
                    algorithm: totp_algo.clone(),
                    digits: *totp_digits,
                    period: *totp_period,
                    issuer: None,
                });

                let needs_password = resource_type.as_deref().map_or_else(
                    || totp.is_none() && pin_code.is_none() && note.is_none(),
                    |slug| {
                        matches!(
                            slug,
                            "password-string"
                                | "password-and-description"
                                | "password-description-totp"
                                | "v5-default"
                                | "v5-default-with-totp"
                        )
                    },
                );
                let resolved_password = match password {
                    Some(provided_password) => Some(provided_password.clone()),
                    None if needs_password => {
                        Some(read_password("Password: ")?.expose_secret().to_string())
                    }
                    None => None,
                };

                let new_resource = NewResource {
                    resource_type: resource_type.clone(),
                    name: name.clone(),
                    username: username.clone(),
                    uris: uri.clone(),
                    description: description.clone(),
                    note: note.clone(),
                    password: resolved_password,
                    totp,
                    pin_code: pin_code.clone(),
                    folder_parent_id: folder_parent_id.clone(),
                    expired: parse_expiry_opt(expiry.as_ref())?
                        .and_then(|expiry| expiry.as_str().map(String::from)),
                    ..NewResource::default()
                };
                let resource =
                    passbolt_sdk::resource::create::create_resource(client, &new_resource).await?;

                if json_output {
                    output::print_json(&resource)?;
                } else {
                    println!("Created resource: {name} ({})", resource.id);
                }
            }

            CreateEntity::Folder {
                name,
                folder_parent_id,
            } => {
                let folder = passbolt_sdk::folder::create::create_folder(
                    client,
                    name,
                    folder_parent_id.as_deref(),
                )
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
                let user = passbolt_sdk::user::create::create_user(
                    client, username, firstname, lastname, role,
                )
                .await?;
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
                let group =
                    passbolt_sdk::group::create::create_group(client, name, user, manager).await?;
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
                let resource = passbolt_sdk::resource::get::get_resource(client, id).await?;
                let secret =
                    passbolt_sdk::resource::get::get_resource_secret(client, &resource).await?;

                let metadata = client.decrypt_resource_metadata(&resource).await?;

                let name = metadata
                    .as_ref()
                    .and_then(|metadata| metadata.name.as_deref())
                    .unwrap_or(&resource.name);
                let username = metadata
                    .as_ref()
                    .and_then(|metadata| metadata.username.as_deref())
                    .unwrap_or_else(|| resource.username.as_deref().unwrap_or(""));
                let uri = metadata
                    .as_ref()
                    .and_then(ResourceMetadata::uri)
                    .unwrap_or_else(|| resource.uri.as_deref().unwrap_or(""));
                let description = metadata
                    .as_ref()
                    .and_then(|metadata| metadata.description.as_deref())
                    .unwrap_or_else(|| secret.description.as_deref().unwrap_or(""));

                if json_output {
                    let mut resource_json = serde_json::to_value(&resource)?;
                    resource_json["password"] =
                        serde_json::Value::String(secret.password.clone().unwrap_or_default());
                    if metadata.is_some() {
                        resource_json["name"] = serde_json::json!(name);
                        resource_json["username"] = serde_json::json!(username);
                        resource_json["uri"] = serde_json::json!(uri);
                        resource_json["description"] = serde_json::json!(description);
                    }
                    output::print_json(&resource_json)?;
                } else {
                    let expiry = resource
                        .expired
                        .map(|date| date.to_rfc3339())
                        .unwrap_or_default();
                    output::print_kv(&[
                        ("ID", resource.id.as_str()),
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
                let permissions =
                    passbolt_sdk::resource::get::get_resource_permissions(client, id).await?;
                if json_output {
                    output::print_json(&permissions)?;
                } else {
                    let rows: Vec<Vec<String>> = permissions
                        .iter()
                        .map(|permission| {
                            vec![
                                permission.aro.clone().unwrap_or_default(),
                                permission.aro_foreign_key.clone().unwrap_or_default(),
                                permission.type_name().to_string(),
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
                let permissions = client.get_folder_permissions(id).await?;
                if json_output {
                    output::print_json(&permissions)?;
                } else {
                    let rows: Vec<Vec<String>> = permissions
                        .iter()
                        .map(|permission| {
                            vec![
                                permission.aro.clone().unwrap_or_default(),
                                permission.aro_foreign_key.clone().unwrap_or_default(),
                                permission.type_name().to_string(),
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
                        .map(|group_user| {
                            vec![
                                group_user.user_id.clone().unwrap_or_default(),
                                if group_user.is_admin.unwrap_or(false) {
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
                let (code, ttl) = passbolt_sdk::resource::get::get_totp_code(client, id).await?;
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

                let resources = passbolt_sdk::resource::list::list_resources(
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
                    let default_columns = ["ID", "FolderParentID", "Name", "Username", "URI"];
                    let effective_columns: Vec<String> = if column.is_empty() {
                        default_columns
                            .iter()
                            .map(|column| (*column).to_string())
                            .collect()
                    } else {
                        column.clone()
                    };

                    let needs_decrypt = effective_columns.iter().any(|column| {
                        matches!(column.to_lowercase().as_str(), "password" | "description")
                    });

                    let secrets = if needs_decrypt {
                        client.decrypt_secrets_batch(&resources, workers).await?
                    } else {
                        HashMap::new()
                    };

                    let metadatas = client.decrypt_metadata_batch(&resources).await?;

                    let rows: Vec<Vec<String>> = resources
                        .iter()
                        .map(|resource| {
                            let secret = secrets.get(&resource.id);
                            let metadata = metadatas.get(&resource.id);
                            effective_columns
                                .iter()
                                .map(|column| match column.to_lowercase().as_str() {
                                    "id" => resource.id.clone(),
                                    "name" => metadata
                                        .and_then(|metadata| metadata.name.as_deref())
                                        .unwrap_or(&resource.name)
                                        .to_string(),
                                    "username" => metadata
                                        .and_then(|metadata| metadata.username.as_deref())
                                        .unwrap_or_else(|| {
                                            resource.username.as_deref().unwrap_or("")
                                        })
                                        .to_string(),
                                    "uri" => metadata
                                        .and_then(ResourceMetadata::uri)
                                        .unwrap_or_else(|| resource.uri.as_deref().unwrap_or(""))
                                        .to_string(),
                                    "folderparentid" | "folder_parent_id" => {
                                        resource.folder_parent_id.clone().unwrap_or_default()
                                    }
                                    "password" => secret
                                        .and_then(|secret| secret.password.as_deref())
                                        .unwrap_or("")
                                        .to_string(),
                                    "description" => metadata
                                        .and_then(|metadata| metadata.description.as_deref())
                                        .or_else(|| {
                                            secret.and_then(|secret| secret.description.as_deref())
                                        })
                                        .unwrap_or("")
                                        .to_string(),
                                    "created" => resource
                                        .created
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    "modified" => resource
                                        .modified
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    "expired" | "expiry" => resource
                                        .expired
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    _ => String::new(),
                                })
                                .collect()
                        })
                        .collect();

                    let headers: Vec<&str> = effective_columns.iter().map(String::as_str).collect();
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

                let folders = passbolt_sdk::folder::list::list_folders(
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
                    let default_columns = ["ID", "Name", "Parent ID"];
                    let effective_columns: Vec<String> = if column.is_empty() {
                        default_columns
                            .iter()
                            .map(|column| (*column).to_string())
                            .collect()
                    } else {
                        column.clone()
                    };
                    let rows: Vec<Vec<String>> = folders
                        .iter()
                        .map(|folder| {
                            effective_columns
                                .iter()
                                .map(|column| match column.to_lowercase().as_str() {
                                    "id" => folder.id.clone(),
                                    "name" => folder.name.clone(),
                                    "parent id" | "folderparentid" | "folder_parent_id" => {
                                        folder.folder_parent_id.clone().unwrap_or_default()
                                    }
                                    "created" => folder
                                        .created
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    "modified" => folder
                                        .modified
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    _ => String::new(),
                                })
                                .collect()
                        })
                        .collect();
                    let headers: Vec<&str> = effective_columns.iter().map(String::as_str).collect();
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

                let users = passbolt_sdk::user::list::list_users(
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
                    let default_columns = ["ID", "Username", "First Name", "Last Name", "Role"];
                    let effective_columns: Vec<String> = if column.is_empty() {
                        default_columns
                            .iter()
                            .map(|column| (*column).to_string())
                            .collect()
                    } else {
                        column.clone()
                    };
                    let rows: Vec<Vec<String>> = users
                        .iter()
                        .map(|user| {
                            effective_columns
                                .iter()
                                .map(|column| match column.to_lowercase().as_str() {
                                    "id" => user.id.clone(),
                                    "username" => user.username.clone().unwrap_or_default(),
                                    "first name" | "firstname" | "first_name" => {
                                        user.first_name().to_string()
                                    }
                                    "last name" | "lastname" | "last_name" => {
                                        user.last_name().to_string()
                                    }
                                    "role" => user.role_name().to_string(),
                                    "created" => user
                                        .created
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    "modified" => user
                                        .modified
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    _ => String::new(),
                                })
                                .collect()
                        })
                        .collect();
                    let headers: Vec<&str> = effective_columns.iter().map(String::as_str).collect();
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

                let groups = passbolt_sdk::group::list::list_groups(
                    client,
                    user.clone(),
                    manager.clone(),
                    &filters,
                )
                .await?;

                if json_output {
                    output::print_json_with_columns(&groups, column)?;
                } else {
                    let default_columns = ["ID", "Name", "Members"];
                    let effective_columns: Vec<String> = if column.is_empty() {
                        default_columns
                            .iter()
                            .map(|column| (*column).to_string())
                            .collect()
                    } else {
                        column.clone()
                    };
                    let rows: Vec<Vec<String>> = groups
                        .iter()
                        .map(|group| {
                            effective_columns
                                .iter()
                                .map(|column| match column.to_lowercase().as_str() {
                                    "id" => group.id.clone(),
                                    "name" => group.name.clone(),
                                    "members" => group.groups_users.len().to_string(),
                                    "created" => group
                                        .created
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    "modified" => group
                                        .modified
                                        .map(|date| date.to_rfc3339())
                                        .unwrap_or_default(),
                                    _ => String::new(),
                                })
                                .collect()
                        })
                        .collect();
                    let headers: Vec<&str> = effective_columns.iter().map(String::as_str).collect();
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
                let expiry_value = parse_expiry_opt(expiry.as_ref())?;

                let resource = passbolt_sdk::resource::update::update_resource(
                    client,
                    id,
                    name.as_deref(),
                    username.as_deref(),
                    uri.as_deref(),
                    description.as_deref(),
                    password.as_deref(),
                    expiry_value,
                    totp_key.as_deref(),
                    totp_algo.as_deref(),
                    *totp_digits,
                    *totp_period,
                    totp_issuer.as_deref(),
                    *remove_totp,
                )
                .await?;

                if json_output {
                    output::print_json(&resource)?;
                } else {
                    println!("Updated resource: {} ({})", resource.name, resource.id);
                }
            }

            UpdateEntity::Folder { id, name } => {
                let payload = passbolt_sdk::types::UpdateFolderPayload { name: name.clone() };
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
                let user = passbolt_sdk::user::update::update_user(
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
                let group = passbolt_sdk::group::update::update_group(
                    client,
                    id,
                    name.as_deref(),
                    user,
                    manager,
                    delete,
                )
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
                passbolt_sdk::resource::share::share_resource(client, id, user, group, *r#type)
                    .await?;
                println!("Shared resource {id}");
            }
            ShareEntity::Folder {
                id,
                r#type,
                user,
                group,
            } => {
                passbolt_sdk::folder::share::share_folder(client, id, user, group, *r#type).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from_file(text: &str) -> Config {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        Config::load_from(&path).unwrap()
    }

    fn overridden(arguments: &[&str], mut config: Config) -> Config {
        let cli = Cli::try_parse_from(arguments).unwrap();
        apply_cli_overrides(&cli, &mut config).unwrap();
        config
    }

    #[test]
    fn test_overrides_keep_the_file_settings_without_flags() {
        let config = config_from_file(
            "mfa_mode = \"none\"\nmfa_totp_offset = 5\nmfa_retrys = 7\n\
             mfa_delay = \"2s\"\ntimeout = \"30s\"\nworkers = 4\n",
        );

        let config = overridden(&["passbolt", "list", "resource"], config);

        assert_eq!(config.mfa_mode, "none");
        assert_eq!(config.mfa_totp_offset, 5);
        assert_eq!(config.mfa_retrys, 7);
        assert_eq!(config.mfa_delay, "2s");
        assert_eq!(config.timeout, "30s");
        assert_eq!(config.workers, 4);
    }

    #[test]
    fn test_overrides_put_the_flags_over_the_file() {
        let config = config_from_file("mfa_retrys = 7\nworkers = 4\ntimeout = \"30s\"\n");

        let config = overridden(
            &[
                "passbolt",
                "--mfa-retrys",
                "2",
                "--workers",
                "0",
                "--timeout",
                "5s",
                "list",
                "resource",
            ],
            config,
        );

        assert_eq!(config.mfa_retrys, 2);
        assert_eq!(config.workers, 0);
        assert_eq!(config.timeout, "5s");
    }
}
