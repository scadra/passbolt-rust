use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use secrecy::ExposeSecret;
use secstr::SecStr;
use std::collections::{HashMap, VecDeque};
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
        let subtree_ids = collect_subtree_ids(root_id, &all_folders);
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
            .filter(|f| subtree_ids.contains(&f.id))
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
        std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(4)
    } else {
        workers
    }
    .max(1);
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));

    let total = resources.len() as u64;
    let pb = Arc::new(ProgressBar::new(total));
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-"),
    );
    pb.set_message("Decrypting secrets...");

    // Share the crypto material across blocking tasks via Arc
    let pgp_key = client.pgp_key_arc();
    let passphrase = client.passphrase_arc();

    // Fetch the org-wide metadata key once (for v5 resources).
    let metadata_key: Arc<Option<pgp::SignedSecretKey>> = Arc::new(
        client
            .ensure_metadata_key()
            .await
            .unwrap_or_else(|e| {
                eprintln!("[warn] Could not fetch metadata key: {e}");
                None
            })
            .cloned(),
    );

    // Spawn one blocking task per resource; collect (original_index, result)
    let mut set: JoinSet<TaskResult> = JoinSet::new();

    for (idx, resource) in resources.iter().enumerate() {
        let encrypted = extract_secret_data(resource);
        let name = resource.name.clone();
        let folder_parent_id = resource.folder_parent_id.clone();
        let meta_armored: Option<String> = resource
            .metadata_armored
            .as_ref()
            .and_then(|v| v.as_str().map(str::to_owned));
        let meta_key_type = resource.metadata_key_type.clone();
        let key = Arc::clone(&pgp_key);
        let meta_key = Arc::clone(&metadata_key);
        let pass = Arc::clone(&passphrase);
        let pb_clone = Arc::clone(&pb);
        let permit = Arc::clone(&sem).acquire_owned().await?;

        set.spawn_blocking(move || {
            let _permit = permit;
            let result = if encrypted.is_empty() {
                Ok(SecretData::default())
            } else {
                decrypt_secret_sync(&encrypted, &key, pass.expose_secret())
                    .with_context(|| format!("Failed to decrypt '{name}'"))
            };

            // Decrypt v5 metadata synchronously in the same blocking task.
            let meta = meta_armored.as_deref().and_then(|armored| {
                let key_to_use: Option<&pgp::SignedSecretKey> =
                    if meta_key_type.as_deref() == Some("user_key") {
                        Some(key.as_ref())
                    } else {
                        (*meta_key).as_ref()
                    };
                key_to_use.and_then(|k| decrypt_metadata_sync(armored, k, pass.expose_secret()))
            });

            pb_clone.inc(1);
            (idx, folder_parent_id, result, meta)
        });
    }

    // Collect results into index-ordered Vec.
    // Cannot use vec![None; n] because KeePassEntry is not Clone (intentional: ZeroizeOnDrop).
    let mut ordered: Vec<Option<(Option<String>, KeePassEntry)>> =
        (0..resources.len()).map(|_| None).collect();

    while let Some(join_result) = set.join_next().await {
        match join_result {
            Ok((idx, folder_parent_id, Ok(secret), meta)) => {
                let entry = build_entry(&resources[idx], &secret, meta.as_ref());
                ordered[idx] = Some((folder_parent_id, entry));
            }
            Ok((idx, folder_parent_id, Err(e), meta)) => {
                eprintln!("Warning: {e}");
                let entry = build_entry(&resources[idx], &SecretData::default(), meta.as_ref());
                ordered[idx] = Some((folder_parent_id, entry));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Decryption task panicked: {e}"));
            }
        }
    }

    pb.finish_with_message("All secrets decrypted");

    let entries: Vec<(Option<String>, KeePassEntry)> = ordered.into_iter().flatten().collect();

    write_kdbx(output_path, password, entries, &folders)?;

    println!(
        "Exported {} entries to {}",
        resources.len(),
        output_path.display()
    );

    Ok(())
}

/// Extract already-fetched encrypted secret data from a resource.
fn extract_secret_data(resource: &Resource) -> String {
    resource
        .secrets
        .first()
        .and_then(|s| s.data.clone())
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
    meta: Option<&ResourceMetadata>,
) -> KeePassEntry {
    let password = secret
        .password
        .clone()
        .or_else(|| secret.raw.clone())
        .unwrap_or_default();

    // v5: prefer metadata fields; fall back to cleartext resource fields.
    let title = meta
        .and_then(|m| m.name.as_deref())
        .unwrap_or(&resource.name)
        .to_string();
    let username = meta
        .and_then(|m| m.username.as_deref())
        .unwrap_or_else(|| resource.username.as_deref().unwrap_or(""))
        .to_string();
    let url = meta
        .and_then(|m| m.uris.as_ref()?.first()?.uri.as_deref())
        .unwrap_or_else(|| resource.uri.as_deref().unwrap_or(""))
        .to_string();
    let notes = meta
        .and_then(|m| m.description.as_deref())
        .or(secret.description.as_deref())
        .unwrap_or("")
        .to_string();

    let otp = secret.totp.as_ref().map(|t| build_otpauth(resource, t));

    KeePassEntry {
        title,
        username,
        url,
        password,
        notes,
        otp,
    }
}

/// Normalise a base32 secret: uppercase, strip spaces, add `=` padding.
/// Some Passbolt entries omit padding; OTP clients and `KeePass` require it.
fn normalize_base32(s: &str) -> String {
    let s = s.trim().to_uppercase().replace(' ', "");
    let rem = s.len() % 8;
    if rem == 0 {
        s
    } else {
        format!("{}{}", s, "=".repeat(8 - rem))
    }
}

/// Build an `otpauth://totp/` URI for the `KeePass` OTP plugin.
fn build_otpauth(resource: &Resource, totp: &TotpData) -> String {
    let label = resource.name.replace(' ', "%20");
    let secret = normalize_base32(totp.secret_key.as_deref().unwrap_or(""));
    let issuer = totp
        .issuer
        .clone()
        .unwrap_or_else(|| resource.name.clone())
        .replace(' ', "%20");
    let algo = totp.algorithm.as_deref().unwrap_or("SHA1");
    let digits = totp.digits.unwrap_or(6);
    let period = totp.period.unwrap_or(30);

    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm={algo}&digits={digits}&period={period}"
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

    let mut db = Database::new(DatabaseConfig::default());

    if folders.is_empty() {
        // No folder data — flat export
        for (_, e) in entries {
            db.root.children.push(Node::Entry(build_kp_entry(e)));
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
        //     attached to db.root.

        // Step 1: BFS ordering
        let bfs_order = bfs_folders(folders);

        // Step 2: create one Group per folder_id
        let mut groups: HashMap<String, Group> = bfs_order
            .iter()
            .map(|f| {
                (
                    f.id.clone(),
                    Group {
                        name: f.name.clone(),
                        ..Default::default()
                    },
                )
            })
            .collect();

        // Step 3: add entries to the correct group (or db.root)
        for (folder_id, e) in entries {
            let node = Node::Entry(build_kp_entry(e));
            match folder_id.as_deref().and_then(|fid| groups.get_mut(fid)) {
                Some(group) => group.children.push(node),
                None => db.root.children.push(node),
            }
        }

        // Step 4: assemble tree in reverse-BFS order (deepest first)
        for folder in bfs_order.iter().rev() {
            if let Some(group) = groups.remove(&folder.id) {
                let node = Node::Group(group);
                match folder
                    .folder_parent_id
                    .as_deref()
                    .and_then(|pid| groups.get_mut(pid))
                {
                    Some(parent) => parent.children.push(node),
                    None => db.root.children.push(node),
                }
            }
        }
    }

    let key = DatabaseKey::new().with_password(password);

    let mut file =
        std::fs::File::create(path).with_context(|| format!("Cannot create {}", path.display()))?;

    db.save(&mut file, key)
        .with_context(|| format!("Cannot write KDBX to {}", path.display()))?;

    Ok(())
}

/// Build a keepass `Entry` from our intermediate representation.
///
/// Uses `std::mem::take` to move each field out without triggering borrow
/// conflicts with the `Drop` impl added by `ZeroizeOnDrop`.  After all takes,
/// `e` holds only empty/None values and is then zeroized on drop.
fn build_kp_entry(mut e: KeePassEntry) -> keepass::db::Entry {
    use keepass::db::{Entry, Value};
    use std::mem::take;

    let mut entry = Entry::new();
    entry
        .fields
        .insert("Title".into(), Value::Unprotected(take(&mut e.title)));
    entry
        .fields
        .insert("UserName".into(), Value::Unprotected(take(&mut e.username)));
    entry
        .fields
        .insert("URL".into(), Value::Unprotected(take(&mut e.url)));
    entry.fields.insert(
        "Password".into(),
        Value::Protected(SecStr::new(take(&mut e.password).into_bytes())),
    );
    entry
        .fields
        .insert("Notes".into(), Value::Unprotected(take(&mut e.notes)));

    if let Some(otp) = take(&mut e.otp) {
        entry.fields.insert(
            "otp".into(),
            Value::Protected(SecStr::new(otp.into_bytes())),
        );
    }

    entry
}

/// Collect all folder IDs in the subtree rooted at `root_id` (inclusive).
fn collect_subtree_ids(root_id: &str, folders: &[Folder]) -> std::collections::HashSet<String> {
    let mut ids = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root_id.to_owned());
    while let Some(current) = queue.pop_front() {
        if let Some(f) = folders.iter().find(|f| f.id == current) {
            ids.insert(f.id.clone());
            for child in folders.iter().filter(|c| {
                c.folder_parent_id
                    .as_deref()
                    .is_some_and(|pid| pid == current)
            }) {
                queue.push_back(child.id.clone());
            }
        }
    }
    ids
}

/// Return folders in BFS order (parents before children).
fn bfs_folders(folders: &[Folder]) -> Vec<&Folder> {
    let mut result: Vec<&Folder> = Vec::with_capacity(folders.len());
    let mut queue: VecDeque<&Folder> = folders
        .iter()
        .filter(|f| f.folder_parent_id.is_none())
        .collect();

    while let Some(f) = queue.pop_front() {
        result.push(f);
        for child in folders
            .iter()
            .filter(|c| c.folder_parent_id.as_deref().is_some_and(|pid| pid == f.id))
        {
            queue.push_back(child);
        }
    }

    // Append any orphaned folders (parent not in list) so they're not lost
    for f in folders {
        if !result.iter().any(|r| r.id == f.id) {
            result.push(f);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use passbolt_sdk::types::TotpData;

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

    fn make_totp(secret: &str, issuer: Option<&str>) -> TotpData {
        TotpData {
            secret_key: Some(secret.into()),
            algorithm: Some("SHA1".into()),
            digits: Some(6),
            period: Some(30),
            issuer: issuer.map(std::convert::Into::into),
        }
    }

    // ─── normalize_base32 ─────────────────────────────────────────────────────

    #[test]
    fn test_already_padded() {
        // 16 chars — multiple of 8, no padding needed
        assert_eq!(normalize_base32("JBSWY3DPEHPK3PXP"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_needs_padding() {
        // 8 chars — already aligned; 7 chars needs 1 '='
        let s = normalize_base32("JBSWY3D");
        assert!(s.ends_with('='));
        assert_eq!(s.len() % 8, 0);
    }

    #[test]
    fn test_lowercase_normalised() {
        assert_eq!(normalize_base32("jbswy3dp"), "JBSWY3DP");
    }

    #[test]
    fn test_strips_spaces() {
        assert_eq!(normalize_base32("JBSWY 3DP"), "JBSWY3DP");
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(normalize_base32(""), "");
    }

    // ─── build_otpauth ────────────────────────────────────────────────────────

    #[test]
    fn test_otpauth_uri_format() {
        let resource = make_resource("MyService");
        let totp = make_totp("JBSWY3DPEHPK3PXP", Some("MyIssuer"));
        let uri = build_otpauth(&resource, &totp);
        assert!(uri.starts_with("otpauth://totp/MyService?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=MyIssuer"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn test_otpauth_spaces_in_name() {
        let resource = make_resource("My Service");
        let totp = make_totp("JBSWY3DPEHPK3PXP", Some("Issuer"));
        let uri = build_otpauth(&resource, &totp);
        assert!(uri.contains("totp/My%20Service?"));
    }

    #[test]
    fn test_otpauth_issuer_fallback_to_resource_name() {
        let resource = make_resource("FallbackName");
        let totp = TotpData {
            secret_key: Some("JBSWY3DPEHPK3PXP".into()),
            algorithm: Some("SHA1".into()),
            digits: Some(6),
            period: Some(30),
            issuer: None, // no issuer → fall back to resource.name
        };
        let uri = build_otpauth(&resource, &totp);
        assert!(uri.contains("issuer=FallbackName"));
    }
}
