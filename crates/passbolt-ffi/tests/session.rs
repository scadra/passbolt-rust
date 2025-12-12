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

//! `PassboltClient` against a wiremock server answering the `GPGAuth` login as Passbolt does.

use std::sync::Arc;

use passbolt_ffi::{PassboltClient, PassboltFfiError};
use passbolt_sdk::crypto;
use serde_json::{json, Value};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ADA_PRIVATE: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_private.asc");
const ADA_PUBLIC: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_public.asc");
const ADA_PASSPHRASE: &str = "ada-passphrase";
const ADA_ID: &str = "8b6c3a10-0000-4000-8000-00000000a0da";
const RESOURCE_ID: &str = "7a5b2c30-0000-4000-8000-0000000000e1";
const PASSWORD_AND_DESCRIPTION_ID: &str = "a28a04cd-6f53-518a-967c-9963bf9cec51";

/// A wiremock Passbolt and the runtime serving it: the client blocks on its own runtime.
struct Passbolt {
    runtime: tokio::runtime::Runtime,
    server: MockServer,
}

impl Passbolt {
    fn new() -> Self {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let server = runtime.block_on(MockServer::start());
        let passbolt = Self { runtime, server };
        passbolt.answer_login();
        passbolt
    }

    fn on(&self, http_method: &str, url_path: &str, body: &Value) {
        self.on_status(http_method, url_path, 200, body);
    }

    fn on_status(&self, http_method: &str, url_path: &str, status: u16, body: &Value) {
        let mock = Mock::given(method(http_method))
            .and(path(url_path))
            .respond_with(ResponseTemplate::new(status).set_body_json(envelope(body)));
        self.runtime.block_on(mock.mount(&self.server));
    }

    /// `GPGAuth` stage 1 then 2, and the CSRF cookie on the first GET.
    fn answer_login(&self) {
        let token = format!("gpgauthv1.3.0|36|{}|gpgauthv1.3.0", uuid::Uuid::new_v4());
        let ada_key = crypto::parse_public_key(ADA_PUBLIC).unwrap();
        let challenge = crypto::encrypt_message(token.as_bytes(), &[&ada_key]).unwrap();
        let stage_2 = Mock::given(method("POST"))
            .and(path("/auth/login.json"))
            .and(body_string_contains("user_token_result"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-GPGAuth-Authenticated", "true")
                    .set_body_json(envelope(&json!({"user": {"id": ADA_ID}}))),
            )
            .with_priority(1);
        let stage_1 = Mock::given(method("POST"))
            .and(path("/auth/login.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "X-GPGAuth-User-Auth-Token",
                        php_quotemeta_urlencode(&challenge),
                    )
                    .set_body_json(envelope(&Value::Null)),
            )
            .with_priority(2);
        let me = Mock::given(method("GET"))
            .and(path("/users/me.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Set-Cookie", "csrfToken=csrf-test-token; Path=/")
                    .set_body_json(envelope(&ada())),
            );
        for mock in [stage_2, stage_1, me] {
            self.runtime.block_on(mock.mount(&self.server));
        }
    }

    fn login(&self) -> Arc<PassboltClient> {
        PassboltClient::login(self.server.uri(), ADA_PRIVATE.into(), ADA_PASSPHRASE.into()).unwrap()
    }

    fn requests(&self, http_method: &str, url_path: &str) -> Vec<Value> {
        self.runtime
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .into_iter()
            .filter(|request| {
                request.method.as_str() == http_method && request.url.path() == url_path
            })
            .map(|request| serde_json::from_slice(&request.body).unwrap_or(Value::Null))
            .collect()
    }
}

fn envelope(body: &Value) -> Value {
    json!({"header": {"status": "success", "message": "The operation was successful."}, "body": body})
}

fn ada() -> Value {
    json!({
        "id": ADA_ID,
        "username": "ada@passbolt.test",
        "gpgkey": {"id": "8b6c3a10-0000-4000-8000-000000008888", "armored_key": ADA_PUBLIC}
    })
}

/// PHP `quotemeta(urlencode($armored))`, as the server sends the challenge.
fn php_quotemeta_urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes())
        .collect::<String>()
        .chars()
        .flat_map(|character| match character {
            '.' | '\\' | '+' | '*' | '?' | '[' | '^' | ']' | '$' | '(' | ')' => {
                vec!['\\', character]
            }
            character => vec![character],
        })
        .collect()
}

fn resource_types() -> Value {
    json!([{"id": PASSWORD_AND_DESCRIPTION_ID, "slug": "password-and-description", "name": "Password and description"}])
}

/// A v4 resource whose secret is encrypted for ada.
fn resource(secret: &str) -> Value {
    let ada_key = crypto::parse_public_key(ADA_PUBLIC).unwrap();
    json!({
        "id": RESOURCE_ID,
        "name": "GitHub",
        "username": "ada",
        "resource_type_id": PASSWORD_AND_DESCRIPTION_ID,
        "created": "2025-09-16T10:00:00+00:00",
        "modified": "2025-09-16T10:00:00+00:00",
        "secrets": [{"user_id": ADA_ID, "data": crypto::encrypt_message(secret.as_bytes(), &[&ada_key]).unwrap()}]
    })
}

#[test]
fn login_answers_the_gpgauth_challenge() {
    let passbolt = Passbolt::new();

    let client = passbolt.login();

    assert_eq!(client.user_id(), ADA_ID);
    assert_eq!(passbolt.requests("POST", "/auth/login.json").len(), 2);
}

#[test]
fn a_resource_view_is_decrypted_json() {
    let passbolt = Passbolt::new();
    passbolt.on(
        "GET",
        &format!("/resources/{RESOURCE_ID}.json"),
        &resource(r#"{"password":"s3cr3t","description":"prod"}"#),
    );
    passbolt.on("GET", "/resource-types.json", &resource_types());

    let view: Value = serde_json::from_str(
        &passbolt
            .login()
            .get_resource_view(RESOURCE_ID.into())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(view["name"], "GitHub");
    assert_eq!(view["password"], "s3cr3t");
    assert_eq!(view["description"], "prod");
    assert_eq!(view["resource_type"], "password-and-description");
}

#[test]
fn a_resource_is_created_from_json() {
    let passbolt = Passbolt::new();
    passbolt.on_status("GET", "/metadata/types/settings.json", 404, &Value::Null);
    passbolt.on("GET", "/resource-types.json", &resource_types());
    passbolt.on("POST", "/resources.json", &resource("{}"));

    passbolt
        .login()
        .create_resource(r#"{"name": "GitHub", "username": "ada", "password": "s3cr3t"}"#.into())
        .unwrap();

    let created = &passbolt.requests("POST", "/resources.json")[0];
    assert_eq!(created["name"], "GitHub");
    assert_eq!(created["resource_type_id"], PASSWORD_AND_DESCRIPTION_ID);
    assert_eq!(created["secrets"][0]["user_id"], ADA_ID);
}

#[test]
fn an_invalid_resource_json_is_an_invalid_argument() {
    let passbolt = Passbolt::new();

    let error = passbolt
        .login()
        .create_resource(r#"{"nmae": "typo"}"#.into())
        .err()
        .unwrap();

    assert!(
        matches!(error, PassboltFfiError::InvalidArgument { .. }),
        "{error}"
    );
    assert_eq!(passbolt.requests("POST", "/resources.json").len(), 0);
}

#[test]
fn a_resource_moves_into_a_folder() {
    let passbolt = Passbolt::new();
    let folder_id = "5f6e7d8c-0000-4000-8000-0000000000f1";
    passbolt.on(
        "PUT",
        &format!("/move/resource/{RESOURCE_ID}.json"),
        &Value::Null,
    );

    passbolt
        .login()
        .move_resource(RESOURCE_ID.into(), Some(folder_id.into()))
        .unwrap();

    assert_eq!(
        passbolt.requests("PUT", &format!("/move/resource/{RESOURCE_ID}.json")),
        [json!({"folder_parent_id": folder_id})]
    );
}

#[test]
fn an_api_error_keeps_its_status() {
    let passbolt = Passbolt::new();
    passbolt.on_status(
        "DELETE",
        &format!("/resources/{RESOURCE_ID}.json"),
        404,
        &Value::Null,
    );

    let error = passbolt
        .login()
        .delete_resource(RESOURCE_ID.into())
        .unwrap_err();

    assert!(
        matches!(error, PassboltFfiError::Api { status: 404, .. }),
        "{error}"
    );
}
