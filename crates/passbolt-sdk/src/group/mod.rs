pub mod create;
pub mod filter;
pub mod list;
pub mod update;

use std::collections::HashSet;

use crate::types::GroupUserPayload;

/// Build a list of group member payloads from manager and regular member IDs.
///
/// Managers are emitted first with `is_admin = true`.  Members already present
/// in `manager_ids` are skipped to avoid duplicates.
pub fn build_group_members(manager_ids: &[String], member_ids: &[String]) -> Vec<GroupUserPayload> {
    let manager_set: HashSet<&str> = manager_ids.iter().map(String::as_str).collect();
    manager_ids
        .iter()
        .map(|uid| GroupUserPayload {
            user_id: uid.clone(),
            is_admin: true,
            delete: None,
        })
        .chain(
            member_ids
                .iter()
                .filter(|uid| !manager_set.contains(uid.as_str()))
                .map(|uid| GroupUserPayload {
                    user_id: uid.clone(),
                    is_admin: false,
                    delete: None,
                }),
        )
        .collect()
}
