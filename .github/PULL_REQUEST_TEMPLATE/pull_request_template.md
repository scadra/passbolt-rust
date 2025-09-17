##IMPORTANT: PLEASE READ

The best way to propose a feature is to open an issue on the community forum and discuss your 
ideas there before implementing them: https://community.passbolt.com/

This is only a issue tracker for issues related to passbolt-rs (CLI, SDK, WASM and FFI bindings).
For passbolt API, docker, browser extension, in short any other issues 
please use this [the other relevant repositories](https://github.com/passbolt).

Always follow the contribution guidelines when submitting a pull request. 
In particular, make sure existing tests still pass, and add tests for all new behavior. 
When fixing a bug, you may want to add a test to verify the fix.

Please follow the following format:

## ISSUE NAME

This pull request is a (multiple allowed):

* [x] bug fix
* [ ] change of existing behavior
* [ ] new feature

Checklist
* [ ] User stories are present (given, when, then format)
* [ ] `cargo test --workspace` is passing
* [ ] `cargo clippy --workspace -- -D warnings` and `cargo fmt --check` are not triggering new error or warning
* [ ] `bash scripts/license-headers.sh` is passing (new .rs files carry the license header)

### What you did
Describe the big picture of your changes here to communicate to the maintainers why we 
should accept this pull request. If it fixes a bug or resolves a feature request, be sure 
to link to that issue.
