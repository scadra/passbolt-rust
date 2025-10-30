---
paths:
  - "crates/**/tests/**"
  - "crates/**/src/**/*.rs"
---

# Rust tests

- Unit tests in `#[cfg(test)] mod tests`; integration tests in `tests/`, shared helpers in `tests/common/`.
- No network: inject the `FakePassbolt` `HttpClient` from `tests/common`; `wiremock` only for the reqwest transport.
- The fake mirrors `passbolt-pro-api` (controllers, middlewares): never fake a response the real server cannot send.
- Mock data lives in `tests/fixtures/data/*.json` (real API shape), loaded via `tests/common/data.rs`. Tests only state what differs.
- Keys: `tests/fixtures/keys` only, never generate keys in tests.
- One behaviour per test, Arrange/Act/Assert, `snake_case` sentence names in `tests/`, `test_*` in `src`.
- Table cases with `rstest`, parsers with `proptest`.
- Known bug: `#[ignore = "TICKET-ID: what is wrong"]`, and the test must fail for that reason.
- DRY: reuse `common` helpers; no wrapper that only forwards; `unwrap()` unless `expect` adds information.
