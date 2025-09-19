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

use std::collections::BTreeSet;

use passbolt_sdk::group::{create as group_create, update as group_update};
use passbolt_sdk::resource::share;
use passbolt_sdk::user::{create as user_create, update as user_update};
use passbolt_sdk::PassboltError;
use serde_json::{json, Value};

use crate::common::*;

fn share_path() -> String {
    format!("/share/resource/{RESOURCE_ID}.json")
}

fn group_path() -> String {
    format!("/groups/{GROUP_ID}.json")
}

fn fake_serving_shareable_resource(secret: &str, permissions: Value) -> FakePassbolt {
    let fake = fake_serving_resource("password-and-description", secret, permissions);
    fake.on("PUT", &share_path(), Value::Null);
    fake.on(
        "POST",
        &format!("/share/simulate/resource/{RESOURCE_ID}.json"),
        data::share_simulate(),
    );
    fake
}

fn fake_serving_group() -> FakePassbolt {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on("GET", &group_path(), data::group());
    fake.on("PUT", &group_path(), data::group());
    fake
}

fn ada_owner_betty_reader_permissions() -> Value {
    json!([
        data::permission("p-ada", "User", ADA_ID, 15),
        data::permission("p-betty", "User", BETTY_ID, 1)
    ])
}

async fn share_with(
    client: &Client,
    user_ids: &[&str],
    group_ids: &[&str],
    permission_type: i32,
) -> Result<(), PassboltError> {
    let user_ids: Vec<String> = user_ids
        .iter()
        .map(|user_id| (*user_id).to_string())
        .collect();
    let group_ids: Vec<String> = group_ids
        .iter()
        .map(|group_id| (*group_id).to_string())
        .collect();
    share::share_resource(client, RESOURCE_ID, &user_ids, &group_ids, permission_type).await
}

#[tokio::test]
async fn share_with_a_user_adds_a_permission_and_their_secret() {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p","description":"d"}"#,
        ada_owner_permissions(),
    );
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 7).await.unwrap();

    let body = fake.body_of("PUT", &share_path());
    assert_eq!(
        body["permissions"],
        json!([{ "aro": "User", "aro_foreign_key": BETTY_ID, "type": 7 }])
    );
    assert_eq!(secret_user_ids(&body), BTreeSet::from([BETTY_ID]));
    let betty_secret = BETTY.decrypt_json(secret_of(&body, BETTY_ID));
    assert_eq!(
        (&betty_secret["password"], &betty_secret["description"]),
        (&json!("p"), &json!("d"))
    );
}

#[tokio::test]
async fn revoke_deletes_the_existing_permission_without_secrets() {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p"}"#,
        ada_owner_betty_reader_permissions(),
    );
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], -1).await.unwrap();

    let body = fake.body_of("PUT", &share_path());
    assert_eq!(
        body["permissions"],
        json!([{ "id": "p-betty", "aro": "User", "aro_foreign_key": BETTY_ID, "delete": true }])
    );
    assert!(body.get("secrets").is_none());
}

#[tokio::test]
async fn revoke_without_matching_permission_fails_before_sharing() {
    let fake = fake_serving_shareable_resource(r#"{"password":"p"}"#, ada_owner_permissions());
    let client = login_ada(&fake).await;

    let error = share_with(&client, &[BETTY_ID], &[], -1).await.unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("PUT", &share_path()).is_empty());
}

#[tokio::test]
async fn create_group_lists_managers_first_without_duplicates() {
    let fake = FakePassbolt::new();
    fake.on("POST", "/groups.json", data::group());
    let client = login_ada(&fake).await;

    group_create::create_group(
        &client,
        "Ops",
        &[ADA_ID.into(), BETTY_ID.into()],
        &[ADA_ID.into()],
    )
    .await
    .unwrap();

    assert_eq!(
        fake.body_of("POST", "/groups.json")["groups_users"],
        json!([{ "user_id": ADA_ID, "is_admin": true }, { "user_id": BETTY_ID, "is_admin": false }])
    );
}

#[tokio::test]
async fn create_user_resolves_the_role_name() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on("POST", "/users.json", data::user("betty"));
    let client = login_ada(&fake).await;

    user_create::create_user(&client, "betty@passbolt.test", "Betty", "Test", "admin")
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("POST", "/users.json")["role_id"],
        data::role_id("admin")
    );
}

#[tokio::test]
async fn create_user_with_an_unknown_role_fails_before_posting() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    let client = login_ada(&fake).await;

    let error = user_create::create_user(&client, "x@passbolt.test", "X", "Y", "superuser")
        .await
        .unwrap_err();

    assert!(matches!(error, PassboltError::NotFound(_)), "{error:?}");
    assert!(fake.requests_to("POST", "/users.json").is_empty());
}

#[tokio::test]
#[ignore = "SHR-1: sharing with a group does not encrypt the secret for its members"]
async fn share_with_a_group_encrypts_for_the_members_who_gain_access() {
    let fake = fake_serving_shareable_resource(r#"{"password":"p"}"#, ada_owner_permissions());
    let client = login_ada(&fake).await;

    share_with(&client, &[], &[GROUP_ID], 1).await.unwrap();

    assert_eq!(
        secret_user_ids(&fake.body_of("PUT", &share_path())),
        BTreeSet::from([CAROL_ID])
    );
}

#[tokio::test]
#[ignore = "SHR-2: sharing with a user who already has access creates a duplicate permission"]
async fn share_updates_an_existing_permission() {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p"}"#,
        ada_owner_betty_reader_permissions(),
    );
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 15).await.unwrap();

    let body = fake.body_of("PUT", &share_path());
    assert_eq!(
        body["permissions"],
        json!([{ "id": "p-betty", "aro": "User", "aro_foreign_key": BETTY_ID, "type": 15 }])
    );
    assert!(
        body.get("secrets").is_none(),
        "betty already has the secret"
    );
}

#[tokio::test]
#[ignore = "SHR-3: the shared secret is re-serialized, a password-string secret becomes JSON"]
async fn share_keeps_the_secret_unchanged() {
    let fake = fake_serving_resource("password-string", "raw-password", ada_owner_permissions());
    fake.on("PUT", &share_path(), Value::Null);
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 1).await.unwrap();

    assert_eq!(
        BETTY.decrypt(secret_of(&fake.body_of("PUT", &share_path()), BETTY_ID)),
        "raw-password"
    );
}

#[tokio::test]
#[ignore = "GRP-1: adding a group member does not send the secrets they need"]
async fn adding_a_group_member_sends_the_needed_secrets() {
    let fake = fake_serving_group();
    fake.on(
        "PUT",
        &format!("/groups/{GROUP_ID}/dry-run.json"),
        data::group_dry_run("p"),
    );
    let client = login_ada(&fake).await;

    group_update::update_group(&client, GROUP_ID, None, &[CAROL_ID.into()], &[], &[])
        .await
        .unwrap();

    assert_eq!(
        CAROL.decrypt(secret_of(&fake.body_of("PUT", &group_path()), CAROL_ID)),
        "p"
    );
}

#[tokio::test]
#[ignore = "GRP-2: removing a member sends the user id instead of the membership id"]
async fn removing_a_group_member_uses_the_membership_id() {
    let fake = fake_serving_group();
    let client = login_ada(&fake).await;

    group_update::update_group(&client, GROUP_ID, None, &[], &[], &[BETTY_ID.into()])
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("PUT", &group_path())["groups_users"],
        json!([{ "id": data::group_membership_id(BETTY_ID), "delete": true }])
    );
}

#[tokio::test]
#[ignore = "USR-1: update user --role sends the role name as role_id"]
async fn update_user_resolves_the_role_name() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "PUT",
        &format!("/users/{BETTY_ID}.json"),
        data::user("betty"),
    );
    let client = login_ada(&fake).await;

    user_update::update_user(&client, BETTY_ID, None, None, Some("admin"))
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("PUT", &format!("/users/{BETTY_ID}.json"))["role_id"],
        data::role_id("admin")
    );
}
