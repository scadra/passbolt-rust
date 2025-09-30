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

//! In-memory Passbolt API behind the SDK's `HttpClient` trait.
//!
//! Login, MFA and envelopes follow `passbolt_api` (`AuthLoginController`,
//! `GpgAuthenticator`, `MfaRequiredCheckMiddleware`); other endpoints answer
//! canned_response bodies registered by the test.

#![allow(clippy::unused_async_trait_impl)] // synchronous fake behind an async trait

use std::sync::{Arc, Mutex};

use passbolt_sdk::{HttpClient, HttpResponse, TransportError};
use serde_json::{json, Value};

use super::keys::ADA;
use super::{data, ADA_ID, BASE_URL, BETTY_ID, CAROL_ID, CSRF_TOKEN, ERIN_ID};

/// Paths reachable while MFA is pending (`MfaRequiredCheckMiddleware::isRouteWhiteListed`).
const MFA_WHITELIST: [&str; 3] = ["/auth/login", "/auth/logout", "/mfa/verify"];

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: &'static str,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Value>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub const fn json_body(&self) -> &Value {
        self.body.as_ref().unwrap()
    }
}

struct Route {
    method: &'static str,
    path: String,
    status: u16,
    body: Value,
}

#[derive(Default)]
struct State {
    routes: Vec<Route>,
    requests: Vec<RecordedRequest>,
    login_token: Option<String>,
    challenge: Option<String>,
    mfa_code: Option<String>,
    mfa_verified: bool,
    no_csrf_cookie: bool,
    csrf_cookie_sent: bool,
}

/// Clones share their state: keep one to inspect what the SDK sent.
#[derive(Clone)]
pub struct FakePassbolt {
    state: Arc<Mutex<State>>,
}

impl FakePassbolt {
    /// Server where ada can log in.
    pub fn new() -> Self {
        let fake = Self {
            state: Arc::default(),
        };
        fake.on("GET", "/users/me.json", data::user("ada"));
        fake.on("POST", "/auth/logout.json", Value::Null);
        fake
    }

    /// Users (with their public key), resource types and roles.
    pub fn with_directory(&self) {
        let names = ["ada", "betty", "carol", "erin"];
        for (id, name) in [ADA_ID, BETTY_ID, CAROL_ID, ERIN_ID].into_iter().zip(names) {
            self.on("GET", &format!("/users/{id}.json"), data::user(name));
        }
        self.on("GET", "/users.json", data::users(&names));
        self.on("GET", "/resource-types.json", data::resource_types());
        self.on("GET", "/roles.json", data::roles());
    }

    /// Answer `method path` with `body` in a success envelope. Query strings are
    /// ignored; the last registration wins.
    pub fn on(&self, method: &'static str, path: &str, body: Value) {
        self.route(method, path, 200, body);
    }

    pub fn on_error(&self, method: &'static str, path: &str, status: u16) {
        self.route(method, path, status, Value::Null);
    }

    fn route(&self, method: &'static str, path: &str, status: u16, body: Value) {
        let mut state = self.state.lock().unwrap();
        state
            .routes
            .retain(|route| !(route.method == method && route.path == path));
        state.routes.push(Route {
            method,
            path: path.to_string(),
            status,
            body,
        });
    }

    /// TOTP required after login, as `MfaRequiredCheckMiddleware` enforces it.
    pub fn require_mfa(&self, code: &str) {
        self.state.lock().unwrap().mfa_code = Some(code.to_string());
    }

    /// Send `plaintext` as the `GPGAuth` challenge instead of a valid token.
    pub fn send_challenge(&self, plaintext: &str) {
        self.state.lock().unwrap().challenge = Some(plaintext.to_string());
    }

    pub fn without_csrf_cookie(&self) {
        self.state.lock().unwrap().no_csrf_cookie = true;
    }

    pub fn requests_to(&self, method: &str, path: &str) -> Vec<RecordedRequest> {
        let state = self.state.lock().unwrap();
        state
            .requests
            .iter()
            .filter(|request| request.method == method && request.path == path)
            .cloned()
            .collect()
    }

    /// Body of the single `method path` request.
    pub fn body_of(&self, method: &str, path: &str) -> Value {
        let requests = self.requests_to(method, path);
        assert_eq!(requests.len(), 1, "{method} {path} calls");
        requests[0].json_body().clone()
    }

    fn handle(
        &self,
        method: &'static str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> HttpResponse {
        let path_and_query = url.strip_prefix(BASE_URL).unwrap_or(url);
        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((path_and_query, ""));
        let body: Option<Value> = body
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| serde_json::from_slice(bytes).unwrap());
        self.state.lock().unwrap().requests.push(RecordedRequest {
            method,
            path: path.to_string(),
            query: query.to_string(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            body: body.clone(),
        });

        let body = body.unwrap_or(Value::Null);
        match (method, path) {
            ("POST", "/auth/login.json") => self.gpgauth_login(&body),
            ("POST", "/mfa/verify/totp.json") => self.verify_totp(&body),
            _ if self.mfa_pending()
                && !MFA_WHITELIST.iter().any(|prefix| path.starts_with(prefix)) =>
            {
                // The 302 to /mfa/verify/error.json, as seen after reqwest follows it.
                json_response(
                    403,
                    "MFA authentication is required.",
                    "/mfa/verify/error.json",
                    &data::mfa_error(),
                )
            }
            _ => {
                let mut response = self.canned_response(method, path);
                if method == "GET" {
                    self.set_csrf_cookie(&mut response);
                }
                response
            }
        }
    }

    /// Like `CsrfProtectionMiddleware`: the cookie comes with the first GET, not with login.
    fn set_csrf_cookie(&self, response: &mut HttpResponse) {
        let mut state = self.state.lock().unwrap();
        if !state.no_csrf_cookie && !state.csrf_cookie_sent {
            state.csrf_cookie_sent = true;
            // What NativeHttpClient exposes for the `csrfToken` cookie.
            response
                .headers
                .push(("set-cookie-name".into(), format!("csrfToken={CSRF_TOKEN}")));
        }
    }

    fn mfa_pending(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.mfa_code.is_some() && !state.mfa_verified
    }

    fn canned_response(&self, method: &str, path: &str) -> HttpResponse {
        let state = self.state.lock().unwrap();
        state
            .routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .map_or_else(
                || {
                    json_response(
                        404,
                        &format!("fake: no route for {method} {path}"),
                        path,
                        &Value::Null,
                    )
                },
                |route| json_response(route.status, "", path, &route.body),
            )
    }

    fn gpgauth_login(&self, body: &Value) -> HttpResponse {
        const URL: &str = "/auth/login.json";
        if body.pointer("/gpg_auth/keyid").and_then(Value::as_str)
            != Some(ADA.fingerprint().as_str())
        {
            return json_response(
                400,
                "There is no user associated with this key.",
                URL,
                &Value::Null,
            );
        }
        let Some(user_token_result) = body
            .pointer("/gpg_auth/user_token_result")
            .and_then(Value::as_str)
        else {
            let token = format!("gpgauthv1.3.0|36|{}|gpgauthv1.3.0", uuid::Uuid::new_v4());
            let challenge = {
                let mut state = self.state.lock().unwrap();
                let challenge = ADA.encrypt(state.challenge.as_deref().unwrap_or(&token));
                state.login_token = Some(token);
                challenge
            };
            // Stage 1 is a partial success: error envelope with status 200.
            let mut response = envelope(
                200,
                "error",
                "Please decrypt this token.",
                URL,
                &Value::Null,
            );
            response
                .headers
                .push(("X-GPGAuth-Progress".into(), "stage1".into()));
            response.headers.push((
                "X-GPGAuth-User-Auth-Token".into(),
                php_quotemeta_urlencode(&challenge),
            ));
            return response;
        };

        let expected_token = self.state.lock().unwrap().login_token.clone();
        if expected_token.as_deref() != Some(user_token_result) {
            return json_response(400, "The authentication failed.", URL, &Value::Null);
        }
        let mut response = json_response(
            200,
            "You are successfully logged in.",
            URL,
            &data::user("ada"),
        );
        response
            .headers
            .push(("X-GPGAuth-Authenticated".into(), "true".into()));
        response
    }

    fn verify_totp(&self, body: &Value) -> HttpResponse {
        const URL: &str = "/mfa/verify/totp.json";
        {
            let mut state = self.state.lock().unwrap();
            if body["totp"].as_str() != state.mfa_code.as_deref() {
                return json_response(400, "The OTP is not valid.", URL, &Value::Null);
            }
            state.mfa_verified = true;
        }
        let mut response = json_response(
            200,
            "The multi-factor authentication was a success.",
            URL,
            &Value::Null,
        );
        response
            .headers
            .push(("set-cookie-name".into(), "passbolt_mfa=verified".into()));
        response
    }
}

/// PHP `quotemeta(urlencode($s))`, as `GpgAuthenticator` sends the challenge.
fn php_quotemeta_urlencode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes())
        .collect::<String>()
        .replace('.', "\\.")
        .replace('+', "\\+")
}

fn json_response(code: u16, message: &str, url: &str, body: &Value) -> HttpResponse {
    let status = if code >= 400 { "error" } else { "success" };
    envelope(code, status, message, url, body)
}

/// Passbolt JSON envelope.
fn envelope(code: u16, status: &str, message: &str, url: &str, body: &Value) -> HttpResponse {
    let envelope = json!({
        "header": { "id": uuid::Uuid::new_v4().to_string(), "status": status, "servertime": 1_757_000_000,
                    "action": uuid::Uuid::new_v4().to_string(), "message": message, "url": url, "code": code },
        "body": body
    });
    HttpResponse {
        status: code,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&envelope).unwrap(),
    }
}

impl HttpClient for FakePassbolt {
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("GET", url, headers, None))
    }

    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("POST", url, headers, Some(body)))
    }

    async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("PUT", url, headers, Some(body)))
    }

    async fn delete(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("DELETE", url, headers, None))
    }

    async fn delete_with_body(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("DELETE", url, headers, Some(body)))
    }
}
