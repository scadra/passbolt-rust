# Test-only OpenPGP keys

Do not use these keys outside the test suite.

| Key      | Passphrase         | Used as                                |
|----------|--------------------|----------------------------------------|
| ada      | `ada-passphrase`   | logged-in user                         |
| betty    | `betty-passphrase` | second user                            |
| carol    | `carol-passphrase` | group member                           |
| erin     | `erin-passphrase`  | ECC user (Ed25519 + Curve25519 subkey) |
| server   | none               | server identity                        |
| metadata | none               | shared v5 metadata key                 |

All but `erin` are RSA-2048 keys whose primary key also encrypts.
