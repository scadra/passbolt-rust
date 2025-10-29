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

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use secrecy::ExposeSecret;
use secstr::SecStr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use tokio::task::JoinSet;
use zeroize::ZeroizeOnDrop;

use crate::Client;
use passbolt_sdk::crypto;
use passbolt_sdk::types::{Folder, Resource, ResourceMetadata, SecretData, TotpData};

type TaskResult = (
    usize,
    Option<String>,
    Result<SecretData>,
    Option<ResourceMetadata>,
);

/// Export Passbolt resources to a `KeePass` KDBX file, preserving folder hierarchy.
///
/// If `folder_id` is provided, only resources inside that folder subtree are exported.
/// Decryption is parallelised across tokio blocking threads, bounded to `workers` threads
/// (0 = auto-detect number of CPUs).
#[allow(clippy::too_many_lines)]
pub async fn export_keepass(
    client: &Client,
    output_path: &Path,
    password: &str,
    folder_id: Option<&str>,
    workers: usize,
) -> Result<()> {
    let all_folders = client
        .get_folders(passbolt_sdk::FolderQuery::default())
        .await
        .context("Failed to fetch folders")?;

    // When a root folder is specified, compute the set of folder IDs in its subtree.
    let (resources, folders) = if let Some(root_id) = folder_id {
        let subtree_ids = collect_subtree_ids(root_id, &all_folders)?;
        let folder_id_strings: Vec<String> = subtree_ids.iter().cloned().collect();
        let resources = client
            .get_resources(passbolt_sdk::ResourceQuery {
                folder_ids: folder_id_strings,
                ..Default::default()
            })
            .await
            .context("Failed to fetch resources")?;
        // Only keep folders that belong to the subtree
        let folders: Vec<Folder> = all_folders
            .into_iter()
            .filter(|folder| subtree_ids.contains(&folder.id))
            .collect();
        (resources, folders)
    } else {
        let resources = client
            .get_resources(passbolt_sdk::ResourceQuery::default())
            .await
            .context("Failed to fetch resources")?;
        (resources, all_folders)
    };

    let concurrency = if workers == 0 {
        std::thread::available_parallelism().map_or(4, std::num::NonZero::get)
    } else {
        workers
    }
    .max(1);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));

    let total = resources.len() as u64;
    let progress_bar = Arc::new(ProgressBar::new(total));
    progress_bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-"),
    );
    progress_bar.set_message("Decrypting secrets...");

    // Share the crypto material across blocking tasks via Arc
    let pgp_key = client.pgp_key_arc();
    let passphrase = client.passphrase_arc();

    // Fetch the org-wide metadata key once (for v5 resources).
    let metadata_key: Arc<Option<pgp::SignedSecretKey>> = Arc::new(
        client
            .ensure_metadata_key()
            .await
            .unwrap_or_else(|error| {
                eprintln!("[warn] Could not fetch metadata key: {error}");
                None
            })
            .cloned(),
    );

    // Spawn one blocking task per resource; collect (original_index, result)
    let mut tasks: JoinSet<TaskResult> = JoinSet::new();

    for (index, resource) in resources.iter().enumerate() {
        let encrypted = extract_secret_data(resource);
        let name = resource.name.clone();
        let folder_parent_id = resource.folder_parent_id.clone();
        let task_metadata_armored: Option<String> = resource
            .metadata_armored
            .as_ref()
            .and_then(|value| value.as_str().map(str::to_owned));
        let task_metadata_key_type = resource.metadata_key_type.clone();
        let key = Arc::clone(&pgp_key);
        let task_metadata_key = Arc::clone(&metadata_key);
        let task_passphrase = Arc::clone(&passphrase);
        let task_progress_bar = Arc::clone(&progress_bar);
        let permit = Arc::clone(&semaphore).acquire_owned().await?;

        tasks.spawn_blocking(move || {
            let _permit = permit;
            let result = if encrypted.is_empty() {
                Ok(SecretData::default())
            } else {
                decrypt_secret_sync(&encrypted, &key, task_passphrase.expose_secret())
                    .with_context(|| format!("Failed to decrypt '{name}'"))
            };

            // Decrypt v5 metadata synchronously in the same blocking task.
            let metadata = task_metadata_armored.as_deref().and_then(|armored| {
                let key_to_use: Option<&pgp::SignedSecretKey> =
                    if task_metadata_key_type.as_deref() == Some("user_key") {
                        Some(key.as_ref())
                    } else {
                        (*task_metadata_key).as_ref()
                    };
                key_to_use.and_then(|selected_key| {
                    decrypt_metadata_sync(armored, selected_key, task_passphrase.expose_secret())
                })
            });

            task_progress_bar.inc(1);
            (index, folder_parent_id, result, metadata)
        });
    }

    let mut task_results = Vec::with_capacity(resources.len());
    while let Some(join_result) = tasks.join_next().await {
        task_results.push(
            join_result.map_err(|error| anyhow::anyhow!("Decryption task panicked: {error}"))?,
        );
    }

    progress_bar.finish_with_message("Secrets decrypted");

    let (entries, failures) = collect_entries(&resources, task_results);
    let exported = entries.len();

    write_kdbx(output_path, password, entries, &folders)?;

    println!("Exported {exported} entries to {}", output_path.display());

    // A partial backup must not look like a complete one to scripts: report and fail.
    ensure_no_decryption_failure(&failures, resources.len())
}

/// Turn decryption results into index-ordered entries, skipping the resources
/// whose secret could not be decrypted; their errors are returned instead.
fn collect_entries(
    resources: &[Resource],
    task_results: Vec<TaskResult>,
) -> (Vec<(Option<String>, KeePassEntry)>, Vec<anyhow::Error>) {
    // Cannot use vec![None; n] because KeePassEntry is not Clone (intentional: ZeroizeOnDrop).
    let mut ordered: Vec<Option<(Option<String>, KeePassEntry)>> =
        (0..resources.len()).map(|_| None).collect();
    let mut failures = Vec::new();

    for (index, folder_parent_id, secret, metadata) in task_results {
        match secret {
            Ok(secret) => {
                let entry = build_entry(&resources[index], &secret, metadata.as_ref());
                ordered[index] = Some((folder_parent_id, entry));
            }
            Err(error) => failures.push(error),
        }
    }

    (ordered.into_iter().flatten().collect(), failures)
}

fn ensure_no_decryption_failure(failures: &[anyhow::Error], total: usize) -> Result<()> {
    if failures.is_empty() {
        return Ok(());
    }
    for failure in failures {
        eprintln!("Skipped: {failure:#}");
    }
    anyhow::bail!(
        "{} of {total} secrets could not be decrypted and were not exported",
        failures.len()
    )
}

/// Extract already-fetched encrypted secret data from a resource.
fn extract_secret_data(resource: &Resource) -> String {
    resource
        .secrets
        .first()
        .and_then(|secret| secret.data.clone())
        .unwrap_or_default()
}

/// Synchronous metadata decryption for v5 resources — safe to run in a blocking thread.
fn decrypt_metadata_sync(
    armored: &str,
    key: &pgp::SignedSecretKey,
    passphrase: &str,
) -> Option<ResourceMetadata> {
    let plaintext = crypto::decrypt_message(armored, key, passphrase).ok()?;
    let text = String::from_utf8(plaintext).ok()?;
    serde_json::from_str::<ResourceMetadata>(&text).ok()
}

/// Synchronous GPG decryption + JSON parse — safe to run in a blocking thread.
fn decrypt_secret_sync(
    armored: &str,
    key: &pgp::SignedSecretKey,
    passphrase: &str,
) -> Result<SecretData> {
    let plaintext =
        crypto::decrypt_message(armored, key, passphrase).context("GPG decryption failed")?;
    let text = String::from_utf8(plaintext).context("Secret is not valid UTF-8")?;
    Ok(
        serde_json::from_str::<SecretData>(&text).unwrap_or_else(|_| SecretData {
            password: Some(text.clone()),
            raw: Some(text),
            ..Default::default()
        }),
    )
}

// ─── Internal types ───────────────────────────────────────────────────────────

/// Intermediate plaintext representation; zeroized on drop so decrypted
/// passwords do not linger in the heap after the KDBX file is written.
#[derive(ZeroizeOnDrop)]
struct KeePassEntry {
    title: String,
    username: String,
    url: String,
    password: String,
    notes: String,
    otp: Option<String>,
}

fn build_entry(
    resource: &Resource,
    secret: &SecretData,
    metadata: Option<&ResourceMetadata>,
) -> KeePassEntry {
    let password = secret
        .password
        .clone()
        .or_else(|| secret.raw.clone())
        .unwrap_or_default();

    // v5: prefer metadata fields; fall back to cleartext resource fields.
    let title = metadata
        .and_then(|metadata| metadata.name.as_deref())
        .unwrap_or(&resource.name)
        .to_string();
    let username = metadata
        .and_then(|metadata| metadata.username.as_deref())
        .unwrap_or_else(|| resource.username.as_deref().unwrap_or(""))
        .to_string();
    let url = metadata
        .and_then(|metadata| metadata.uris.as_ref()?.first()?.uri.as_deref())
        .unwrap_or_else(|| resource.uri.as_deref().unwrap_or(""))
        .to_string();
    let notes = metadata
        .and_then(|metadata| metadata.description.as_deref())
        .or(secret.description.as_deref())
        .unwrap_or("")
        .to_string();

    let otp = secret
        .totp
        .as_ref()
        .map(|totp| build_otpauth(&title, &username, totp));

    KeePassEntry {
        title,
        username,
        url,
        password,
        notes,
        otp,
    }
}

/// Normalise a base32 secret: uppercase, strip spaces and `=` padding,
/// which the Key URI format omits.
fn normalize_base32(secret: &str) -> String {
    secret
        .trim()
        .to_uppercase()
        .replace(' ', "")
        .trim_end_matches('=')
        .to_owned()
}

/// Percent-encode everything but the RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0F)]));
        }
    }
    encoded
}

/// Build an `otpauth://totp/issuer:account` URI (Google Key URI format) for the
/// `KeePass` OTP plugin. The issuer defaults to the title, the account to the
/// username, then to the title.
fn build_otpauth(title: &str, username: &str, totp: &TotpData) -> String {
    let issuer = totp
        .issuer
        .as_deref()
        .filter(|issuer| !issuer.is_empty())
        .unwrap_or(title);
    let account = if username.is_empty() { title } else { username };
    let label = format!("{}:{}", percent_encode(issuer), percent_encode(account));
    let secret = percent_encode(&normalize_base32(totp.secret_key.as_deref().unwrap_or("")));
    let algorithm = percent_encode(&totp.algorithm.as_deref().unwrap_or("SHA1").to_uppercase());
    let digits = totp.digits.unwrap_or(6);
    let period = totp.period.unwrap_or(30);

    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={}&algorithm={algorithm}&digits={digits}&period={period}",
        percent_encode(issuer)
    )
}

// ─── KDBX writer ─────────────────────────────────────────────────────────────

fn write_kdbx(
    path: &Path,
    password: &str,
    entries: Vec<(Option<String>, KeePassEntry)>,
    folders: &[Folder],
) -> Result<()> {
    use keepass::{
        config::DatabaseConfig,
        db::{Database, Group, Node},
        DatabaseKey,
    };

    let mut database = Database::new(DatabaseConfig::default());

    if folders.is_empty() {
        // No folder data — flat export
        for (_, entry) in entries {
            database
                .root
                .children
                .push(Node::Entry(build_kp_entry(entry)));
        }
    } else {
        // Build folder groups, preserving hierarchy.
        //
        // Algorithm:
        //  1. BFS-order folders (parents before children).
        //  2. Create a keepass Group for each folder.
        //  3. Add entries to the correct group (or root if no folder).
        //  4. Assemble in reverse-BFS order: remove deepest groups first and
        //     attach them to their parent groups, ending with root-level groups
        //     attached to database.root.

        // Step 1: BFS ordering
        let bfs_order = bfs_folders(folders);

        // Step 2: create one Group per folder_id
        let mut groups: HashMap<String, Group> = bfs_order
            .iter()
            .map(|folder| {
                (
                    folder.id.clone(),
                    Group {
                        name: folder.name.clone(),
                        ..Default::default()
                    },
                )
            })
            .collect();

        // Step 3: add entries to the correct group (or database.root)
        for (folder_id, entry) in entries {
            let node = Node::Entry(build_kp_entry(entry));
            match folder_id.as_deref().and_then(|id| groups.get_mut(id)) {
                Some(group) => group.children.push(node),
                None => database.root.children.push(node),
            }
        }

        // Step 4: assemble tree in reverse-BFS order (deepest first)
        for folder in bfs_order.iter().rev() {
            if let Some(group) = groups.remove(&folder.id) {
                let node = Node::Group(group);
                match folder
                    .folder_parent_id
                    .as_deref()
                    .and_then(|parent_id| groups.get_mut(parent_id))
                {
                    Some(parent) => parent.children.push(node),
                    None => database.root.children.push(node),
                }
            }
        }
    }

    let key = DatabaseKey::new().with_password(password);

    let mut file =
        std::fs::File::create(path).with_context(|| format!("Cannot create {}", path.display()))?;

    database
        .save(&mut file, key)
        .with_context(|| format!("Cannot write KDBX to {}", path.display()))?;

    Ok(())
}

/// Build a keepass `Entry` from our intermediate representation.
///
/// Uses `std::mem::take` to move each field out without triggering borrow
/// conflicts with the `Drop` impl added by `ZeroizeOnDrop`.  After all takes,
/// `source` holds only empty/None values and is then zeroized on drop.
fn build_kp_entry(mut source: KeePassEntry) -> keepass::db::Entry {
    use keepass::db::{Entry, Value};
    use std::mem::take;

    let mut entry = Entry::new();
    entry
        .fields
        .insert("Title".into(), Value::Unprotected(take(&mut source.title)));
    entry.fields.insert(
        "UserName".into(),
        Value::Unprotected(take(&mut source.username)),
    );
    entry
        .fields
        .insert("URL".into(), Value::Unprotected(take(&mut source.url)));
    entry.fields.insert(
        "Password".into(),
        Value::Protected(SecStr::new(take(&mut source.password).into_bytes())),
    );
    entry
        .fields
        .insert("Notes".into(), Value::Unprotected(take(&mut source.notes)));

    if let Some(otp) = take(&mut source.otp) {
        entry.fields.insert(
            "otp".into(),
            Value::Protected(SecStr::new(otp.into_bytes())),
        );
    }

    entry
}

/// Collect all folder IDs in the subtree rooted at `root_id` (inclusive).
fn collect_subtree_ids(root_id: &str, folders: &[Folder]) -> Result<HashSet<String>> {
    if !folders.iter().any(|folder| folder.id == root_id) {
        anyhow::bail!("folder {root_id} not found");
    }
    let mut ids = HashSet::new();
    let mut queue = VecDeque::from([root_id.to_owned()]);
    while let Some(current) = queue.pop_front() {
        if !ids.insert(current.clone()) {
            continue;
        }
        for child in folders.iter().filter(|candidate| {
            candidate
                .folder_parent_id
                .as_deref()
                .is_some_and(|parent_id| parent_id == current)
        }) {
            queue.push_back(child.id.clone());
        }
    }
    Ok(ids)
}

/// Return folders in BFS order (parents before children). A folder whose
/// parent is not in `folders` is a root, so an exported sub-folder keeps its tree.
fn bfs_folders(folders: &[Folder]) -> Vec<&Folder> {
    let exported_ids: HashSet<&str> = folders.iter().map(|folder| folder.id.as_str()).collect();
    let mut result: Vec<&Folder> = Vec::with_capacity(folders.len());
    let mut queue: VecDeque<&Folder> = folders
        .iter()
        .filter(|folder| {
            folder
                .folder_parent_id
                .as_deref()
                .is_none_or(|parent_id| !exported_ids.contains(parent_id))
        })
        .collect();

    while let Some(folder) = queue.pop_front() {
        result.push(folder);
        for child in folders.iter().filter(|candidate| {
            candidate
                .folder_parent_id
                .as_deref()
                .is_some_and(|parent_id| parent_id == folder.id)
        }) {
            queue.push_back(child);
        }
    }

    // Append the folders of a parent cycle, unreachable from any root, so they're not lost
    for folder in folders {
        if !result.iter().any(|added| added.id == folder.id) {
            result.push(folder);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{Database, Node, Value};
    use keepass::DatabaseKey;
    use passbolt_sdk::types::ResourceUri;
    use rstest::rstest;

    const SERVER_PRIVATE: &str =
        include_str!("../../../passbolt-sdk/tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str =
        include_str!("../../../passbolt-sdk/tests/fixtures/keys/server_public.asc");
    const METADATA_PRIVATE: &str =
        include_str!("../../../passbolt-sdk/tests/fixtures/keys/metadata_private.asc");

    fn make_resource(name: &str) -> Resource {
        Resource {
            id: "test-id".into(),
            name: name.into(),
            username: None,
            uri: None,
            description: None,
            folder_parent_id: None,
            resource_type_id: None,
            created: None,
            modified: None,
            created_by: None,
            modified_by: None,
            personal: None,
            favorite: None,
            secrets: vec![],
            permissions: vec![],
            metadata_armored: None,
            metadata_key_id: None,
            metadata_key_type: None,
            expired: None,
        }
    }

    fn make_folder(id: &str, parent_id: Option<&str>) -> Folder {
        Folder {
            id: id.into(),
            name: format!("{id}-name"),
            folder_parent_id: parent_id.map(Into::into),
            created: None,
            modified: None,
            created_by: None,
            modified_by: None,
            personal: None,
            permissions: vec![],
        }
    }

    fn make_totp(secret: &str, issuer: Option<&str>) -> TotpData {
        TotpData {
            secret_key: Some(secret.into()),
            algorithm: Some("SHA1".into()),
            digits: Some(6),
            period: Some(30),
            issuer: issuer.map(Into::into),
        }
    }

    fn make_entry(title: &str, otp: Option<&str>) -> KeePassEntry {
        KeePassEntry {
            title: title.into(),
            username: String::new(),
            url: String::new(),
            password: format!("{title}-password"),
            notes: String::new(),
            otp: otp.map(Into::into),
        }
    }

    fn encrypt_for_server(plaintext: &str) -> String {
        let public_key = crypto::parse_public_key(SERVER_PUBLIC).unwrap();
        crypto::encrypt_message(plaintext.as_bytes(), &[&public_key]).unwrap()
    }

    fn server_private_key() -> pgp::SignedSecretKey {
        crypto::parse_private_key(SERVER_PRIVATE)
            .unwrap()
            .key
            .clone()
    }

    fn folder_ids<'a>(folders: &[&'a Folder]) -> Vec<&'a str> {
        folders.iter().map(|folder| folder.id.as_str()).collect()
    }

    fn child_group<'a>(group: &'a keepass::db::Group, name: &str) -> &'a keepass::db::Group {
        group
            .children
            .iter()
            .find_map(|node| match node {
                Node::Group(child) if child.name == name => Some(child),
                _ => None,
            })
            .unwrap()
    }

    fn child_entries(group: &keepass::db::Group) -> Vec<&keepass::db::Entry> {
        group
            .children
            .iter()
            .filter_map(|node| match node {
                Node::Entry(entry) => Some(entry),
                Node::Group(_) => None,
            })
            .collect()
    }

    #[rstest]
    #[case::already_aligned("JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP")]
    #[case::padding_removed("JBSWY3D=", "JBSWY3D")]
    #[case::lowercase("jbswy3dp", "JBSWY3DP")]
    #[case::spaces("JBSWY 3DP", "JBSWY3DP")]
    #[case::empty("", "")]
    fn test_normalize_base32(#[case] secret: &str, #[case] expected: &str) {
        assert_eq!(normalize_base32(secret), expected);
    }

    #[rstest]
    #[case::plain(
        "MyService",
        "alice",
        make_totp("JBSWY3DPEHPK3PXP", Some("MyIssuer")),
        "otpauth://totp/MyIssuer:alice?secret=JBSWY3DPEHPK3PXP&issuer=MyIssuer&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::special_characters(
        "Title",
        "me&you?#a:b/c",
        make_totp("jbswy3d=", Some("A&B?C#D:E/F G")),
        "otpauth://totp/A%26B%3FC%23D%3AE%2FF%20G:me%26you%3F%23a%3Ab%2Fc?secret=JBSWY3D&issuer=A%26B%3FC%23D%3AE%2FF%20G&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::defaults(
        "My Service",
        "",
        TotpData { secret_key: Some("JBSWY3DP".into()), algorithm: None, digits: None, period: None, issuer: None },
        "otpauth://totp/My%20Service:My%20Service?secret=JBSWY3DP&issuer=My%20Service&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::empty_issuer_falls_back_to_title(
        "Fallback",
        "bob",
        make_totp("JBSWY3DP", Some("")),
        "otpauth://totp/Fallback:bob?secret=JBSWY3DP&issuer=Fallback&algorithm=SHA1&digits=6&period=30"
    )]
    fn test_build_otpauth(
        #[case] title: &str,
        #[case] username: &str,
        #[case] totp: TotpData,
        #[case] expected: &str,
    ) {
        assert_eq!(build_otpauth(title, username, &totp), expected);
    }

    #[test]
    fn test_collect_subtree_ids_returns_root_and_descendants_only() {
        let folders = vec![
            make_folder("top", None),
            make_folder("root", Some("top")),
            make_folder("grandchild", Some("child")),
            make_folder("child", Some("root")),
            make_folder("sibling", Some("top")),
        ];

        let ids = collect_subtree_ids("root", &folders).unwrap();

        let expected: HashSet<String> = ["root", "child", "grandchild"]
            .into_iter()
            .map(Into::into)
            .collect();
        assert_eq!(ids, expected);
    }

    #[test]
    fn test_collect_subtree_ids_fails_on_unknown_root() {
        let folders = vec![make_folder("top", None)];

        let error = collect_subtree_ids("missing", &folders).unwrap_err();

        assert_eq!(error.to_string(), "folder missing not found");
    }

    #[test]
    fn test_collect_subtree_ids_stops_on_cycle() {
        let folders = vec![
            make_folder("first", Some("second")),
            make_folder("second", Some("first")),
        ];

        let ids = collect_subtree_ids("first", &folders).unwrap();

        assert_eq!(ids.len(), 2);
    }

    #[rstest]
    #[case::full_vault(
        vec![make_folder("child", Some("top")), make_folder("top", None)],
        vec!["top", "child"]
    )]
    #[case::subtree_root_listed_after_child(
        vec![make_folder("child", Some("sub")), make_folder("sub", Some("outside"))],
        vec!["sub", "child"]
    )]
    #[case::cycle_kept(
        vec![make_folder("first", Some("second")), make_folder("second", Some("first"))],
        vec!["first", "second"]
    )]
    fn test_bfs_folders_orders_parents_first(
        #[case] folders: Vec<Folder>,
        #[case] expected: Vec<&str>,
    ) {
        assert_eq!(folder_ids(&bfs_folders(&folders)), expected);
    }

    #[test]
    fn test_write_kdbx_keeps_hierarchy_of_exported_subtree() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.kdbx");
        let folders = vec![
            make_folder("child", Some("sub")),
            make_folder("sub", Some("outside")),
        ];
        let entries = vec![
            (None, make_entry("at-root", None)),
            (
                Some("child".to_owned()),
                make_entry("nested", Some("otpauth://totp/Issuer:me?secret=JBSWY3DP")),
            ),
        ];

        write_kdbx(&path, "master", entries, &folders).unwrap();

        let mut file = std::fs::File::open(&path).unwrap();
        let database =
            Database::open(&mut file, DatabaseKey::new().with_password("master")).unwrap();
        let root_entries = child_entries(&database.root);
        assert_eq!(root_entries.len(), 1);
        assert_eq!(root_entries[0].get_title(), Some("at-root"));
        assert_eq!(root_entries[0].get_password(), Some("at-root-password"));
        let sub = child_group(&database.root, "sub-name");
        let child = child_group(sub, "child-name");
        let nested = child_entries(child);
        assert_eq!(nested[0].get_title(), Some("nested"));
        assert!(matches!(
            nested[0].fields.get("otp"),
            Some(Value::Protected(_))
        ));
        assert_eq!(
            nested[0].get("otp"),
            Some("otpauth://totp/Issuer:me?secret=JBSWY3DP")
        );
    }

    #[test]
    fn test_build_entry_prefers_v5_metadata_over_clear_fields() {
        let mut resource = make_resource("clear-name");
        resource.username = Some("clear-user".into());
        resource.uri = Some("https://clear.example".into());
        let secret = SecretData {
            password: Some("secret".into()),
            description: Some("secret-description".into()),
            ..Default::default()
        };
        let metadata = ResourceMetadata {
            object_type: Some("PASSBOLT_RESOURCE_METADATA".into()),
            name: Some("meta-name".into()),
            username: Some("meta-user".into()),
            uris: Some(vec![ResourceUri {
                uri: Some("https://meta.example".into()),
                match_field: None,
            }]),
            description: Some("meta-description".into()),
        };

        let entry = build_entry(&resource, &secret, Some(&metadata));

        assert_eq!(entry.title, "meta-name");
        assert_eq!(entry.username, "meta-user");
        assert_eq!(entry.url, "https://meta.example");
        assert_eq!(entry.notes, "meta-description");
    }

    #[test]
    fn test_build_entry_password_falls_back_to_raw() {
        let secret = SecretData {
            raw: Some("raw-secret".into()),
            ..Default::default()
        };

        let entry = build_entry(&make_resource("name"), &secret, None);

        assert_eq!(entry.password, "raw-secret");
    }

    #[test]
    fn test_decrypt_secret_sync_uses_non_json_secret_as_password() {
        let armored = encrypt_for_server("not json");

        let secret = decrypt_secret_sync(&armored, &server_private_key(), "").unwrap();

        assert_eq!(secret.password.as_deref(), Some("not json"));
        assert_eq!(secret.raw.as_deref(), Some("not json"));
    }

    #[test]
    fn test_decrypt_secret_sync_parses_json_secret() {
        let armored = encrypt_for_server(r#"{"password":"p4ss","description":"notes"}"#);

        let secret = decrypt_secret_sync(&armored, &server_private_key(), "").unwrap();

        assert_eq!(secret.password.as_deref(), Some("p4ss"));
        assert_eq!(secret.description.as_deref(), Some("notes"));
    }

    #[test]
    fn test_decrypt_secret_sync_fails_with_wrong_key() {
        let armored = encrypt_for_server("secret");
        let wrong_key = crypto::parse_private_key(METADATA_PRIVATE)
            .unwrap()
            .key
            .clone();

        assert!(decrypt_secret_sync(&armored, &wrong_key, "").is_err());
    }

    #[test]
    fn test_collect_entries_skips_and_counts_decryption_failures() {
        let resources = vec![make_resource("decrypted"), make_resource("broken")];
        let task_results: Vec<TaskResult> = vec![
            (
                1,
                None,
                Err(anyhow::anyhow!("Failed to decrypt 'broken'")),
                None,
            ),
            (
                0,
                None,
                Ok(SecretData {
                    password: Some("secret".into()),
                    ..Default::default()
                }),
                None,
            ),
        ];

        let (entries, failures) = collect_entries(&resources, task_results);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.title, "decrypted");
        assert_eq!(failures.len(), 1);
    }

    #[test]
    fn test_ensure_no_decryption_failure_reports_count() {
        let failures = vec![anyhow::anyhow!("Failed to decrypt 'broken'")];

        let error = ensure_no_decryption_failure(&failures, 3).unwrap_err();

        assert_eq!(
            error.to_string(),
            "1 of 3 secrets could not be decrypted and were not exported"
        );
    }

    #[test]
    fn test_ensure_no_decryption_failure_accepts_complete_export() {
        assert!(ensure_no_decryption_failure(&[], 3).is_ok());
    }
}
