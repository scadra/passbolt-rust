# passbolt-rust — tickets de parité avec go-passbolt / go-passbolt-cli

Référence Go : go-passbolt-cli 5ad2e0f, go-passbolt main.
Source : lecture du code uniquement (aucun build, aucun test contre un serveur). Les tickets marqués (?) sont à confirmer sur un serveur v5.

## P1 — Sécurité

| # | Ticket | Preuves Rust |
|---|---|---|
| SEC-1 | Redirections suivies vers un autre hôte avec le X-CSRF-Token et le corps gpg_auth : n'autoriser que le même schéma et le même hôte | sdk/platform/native.rs:25-28 |
| SEC-2 | Vérification serveur cassée : GET au lieu de POST, champ `challenge` inexistant, contrôle toujours sauté, empreinte stockée dans `server_verify_enc_token` | sdk/auth.rs:213-274, cli/cli/verify.rs:33-47 |
| SEC-3 | Le contrôle de la clé après login avale toutes les erreurs (`if let Ok`), il ne vérifie donc rien | sdk/client.rs:166-178 |
| SEC-4 | Clé de métadonnées partagée : ni vérification de signature ni épinglage de l'empreinte | sdk/client.rs:37-84 |
| SEC-5 | IDs non validés (UUID) avant interpolation dans les chemins d'URL, y compris `exec passbolt://…` | sdk/client.rs:640,726,895,1034 ; cli/cli/exec.rs:29-33 |

## P2 — Sécurité

| # | Ticket | Preuves Rust |
|---|---|---|
| SEC-6 | Pas de validation du format du token GPGAuth (`gpgauthv1.3.0\|36\|uuid\|…`), le client peut servir d'oracle de déchiffrement | sdk/auth.rs:80-88 |
| SEC-7 | Session acceptée sans cookie, sans CSRF ou sans user_id | sdk/auth.rs:195-205 |
| SEC-8 | Messages chiffrés non signés (Go signe avec la clé utilisateur, plus la clé de métadonnées en v5) | sdk/crypto.rs:66-84 |
| SEC-9 | Zeroization incomplète, logout qui ignore les erreurs et garde les clés en cache, `pgp_key_arc`/`passphrase_arc` exposés | sdk/crypto.rs:15-63, client.rs:185-189,601-606 |

## P3 — Sécurité

| # | Ticket | Preuves Rust |
|---|---|---|
| SEC-10 | Refuser `http://` (durcissement, Go ne le fait pas non plus) | sdk/client.rs:96-102 |

## P1 — Ressources v4/v5 (SDK)

| # | Ticket | Preuves Rust |
|---|---|---|
| RES-1 | Création toujours en v4 : les réglages de type de métadonnées sont ignorés, name/username/uri partent en clair | sdk/resource/create.rs:22-76 |
| RES-2 | Update d'une ressource v5 : métadonnées envoyées en clair, sans rechiffrement | sdk/resource/update.rs:122-130 |
| RES-3 | Update : rechiffrement seulement pour les permissions `aro=User`, les membres des groupes sont oubliés | sdk/resource/update.rs:39-44 |
| RES-4 | Le secret est reconstruit en `{password,description,totp}` : password-string, custom fields et object_type sont corrompus ; le resource_type ne suit pas l'ajout ou le retrait du TOTP | sdk/resource/update.rs:49-109, types.rs:132-142 |
| RES-5 | `update --description` seul est ignoré en silence | sdk/resource/update.rs:26-32,126 |
| RES-6 (?) | `uris` modélisé comme une liste d'objets au lieu d'une liste de chaînes : la désérialisation des métadonnées v5 échoue, `list` sort vide | sdk/types.rs:104-116 |
| RES-7 (?) | Clé privée de métadonnées parsée comme une clé armurée alors que c'est du JSON `{armored_key,passphrase}` : le déchiffrement shared_key échoue | sdk/client.rs:73-79 |

## P2 — Ressources v4/v5 (SDK)

| # | Ticket | Preuves Rust |
|---|---|---|
| RES-8 | Pas de slugs v5 (default, password-string, totp-standalone, default-with-totp, custom-fields, note, pin-code) ni de custom fields ; pas de `--type/--field/--secret-field` | sdk/types.rs:104-142, cli/cli/root.rs:162-199 |
| RES-9 | Pas de validation par schéma JSON des métadonnées et du secret | — |
| RES-10 | Chiffrement des métadonnées incomplet : `metadata_key_id` vide en mode personnel ; le mode partagé ne récupère pas la clé publique ; la clé la plus récente n'est pas choisie ; `allow_usage_of_personal_keys` est ignoré | sdk/client.rs:37-85,1191-1215 |
| RES-11 | `metadata_key_id` de la ressource ignoré (casse après rotation) ; OnceLock met `None` en cache pour toujours | sdk/client.rs:66-69,458-494 |
| RES-12 | Erreur de recherche du resource_type avalée à la création (`.ok().flatten()`) | sdk/resource/create.rs:55-59 |
| RES-13 | Decrypt batch : les erreurs sont avalées, ce qui donne un SecretData vide (risque d'écraser le secret) | sdk/client.rs:557-590 |
| RES-14 | Réglages password-expiry mal mappés (`default_expiry_period`) et jamais appliqués à la création ou à l'update | sdk/types.rs:556-568 |
| RES-15 (?) | `Resource.name: String` obligatoire, alors que v5 peut l'omettre ; `is_v5()` basé sur metadata_key_id | sdk/types.rs:28,67 |
| RES-16 | Pas de `/settings.json` au login (détection des plugins, choix v4/v5) | — |

## P3 — Ressources v4/v5 (SDK)

| # | Ticket | Preuves Rust |
|---|---|---|
| RES-17 | Expiration : accepter `w` et les combinaisons (`1w2d3h`) | sdk/resource/expiry.rs:25-45 |
| RES-18 | `get` : description perdue en v4 password-string, JSON incomplet, custom fields non affichés | cli/main.rs:297-311 |

## P1 — Partage, groupes, utilisateurs

| # | Ticket | Preuves Rust |
|---|---|---|
| SHR-1 | Partage avec un groupe : secret non chiffré pour ses membres. Utiliser `/share/simulate` puis `changes.added` | sdk/resource/share.rs:41-46 |
| SHR-2 | Partage : une permission existante n'est jamais modifiée (`id: None`), ce qui crée un doublon ou une erreur ; dossiers inclus | sdk/types.rs:453-476, folder/share.rs:32 |
| SHR-3 | Partage : le secret est resérialisé depuis SecretData, d'où sa corruption. Rechiffrer le clair tel quel | sdk/resource/share.rs:36-38 |
| SHR-4 | Partage d'une ressource v5 personnelle : les métadonnées ne basculent pas sur la clé partagée | sdk/resource/share.rs |
| GRP-1 | Ajout d'un membre à un groupe sans dry-run ni `secrets` | sdk/group/update.rs, types.rs:424-437 |
| GRP-2 | Retrait d'un membre et changement de rôle impossibles (pas d'`id` de membership) | sdk/group/update.rs:16-22 |
| USR-1 | `update user --role` envoie le nom du rôle comme `role_id` | sdk/user/update.rs:13 |

## P2 — Partage, groupes, utilisateurs

| # | Ticket | Preuves Rust |
|---|---|---|
| SHR-5 | Révocation : un ARO sans permission est ignoré en silence ; `-t` n'est pas validé (1/7/15) | sdk/types.rs:487-490 |
| GRP-3 | `get group` : pas de username/nom des membres ; `-c` ignoré | cli/main.rs:400-420 |
| LST-1 (?) | Filtres de liste faux ou non répétables : `is-in-group` au lieu de `has-group[]`, `has-access` sans `[]`, `is-shared-with-group` sur les dossiers | sdk/client.rs:757-816 |

## P3 — Partage, groupes, utilisateurs

| # | Ticket | Preuves Rust |
|---|---|---|
| USR-2 (?) | Dry-run de suppression en GET au lieu de DELETE ; pas de prévisualisation dans le CLI | sdk/client.rs:1132-1141 |
| USR-3 | `update user` envoie un profil partiel, sans fusion avec le profil actuel | sdk/user/update.rs:15-24 |
| SHR-6 | Documenter qu'un partage de dossier ne propage pas les permissions (même comportement que Go) | — |

## P1 — Métadonnées, session keys, infra

| # | Ticket | Preuves Rust |
|---|---|---|
| MTA-1 | Session keys absentes : pas de fetch ni de cache, pas de sauvegarde avant logout, pas de CRUD `/metadata/session-keys` | — |

## P2 — Métadonnées, session keys, infra

| # | Ticket | Preuves Rust |
|---|---|---|
| MTA-2 | Caches absents : resource types, pré-déchiffrement des clés de métadonnées ; N+1 GET user dans `encrypt_secret_for_users` | sdk/client.rs:717-744,944-950 |
| MFA-1 | Retries sans délai, pas de contrôle du provider, pas de normalisation du secret TOTP, détection MFA trop large (tout 403) | sdk/auth.rs:104-172 |

## P3 — Métadonnées, session keys, infra

| # | Ticket | Preuves Rust |
|---|---|---|
| API-1 | Endpoints manquants : healthcheck, gpgkeys, setup de compte (install/complete), update comment | — |
| API-2 | User-Agent ; certificat mTLS sans clé ignoré en silence | sdk/platform/native.rs:31-59 |
| API-3 | Erreurs typées (SessionNotFound, InvalidUUID…) et indications par code HTTP (401/403/404/5xx) | sdk/error.rs |

## P1 — CLI : compatibilité go-passbolt-cli

| # | Ticket | Preuves Rust |
|---|---|---|
| CLI-1 | `--config` déclaré mais jamais lu | cli/config.rs:85-86 |
| CLI-2 | `--timeout` et `--mfa-delay` sans effet | cli/config.rs:138-154, native.rs:10-15 |
| CLI-3 | Mode MFA `noninteractive-totp` (Go) non reconnu, retombe sur interactif ; défaut différent | cli/util/session.rs:33-40 |
| CLI-4 | Pas de demande du mot de passe utilisateur (TTY ou stdin) : login avec passphrase vide | cli/config.rs:143, cli/verify.rs:21-26 |
| CLI-5 | `--user-private-key-file` n'écrase pas la clé inline de la config | cli/config.rs:159-165 |
| CLI-6 | Flags camelCase de Go (`--serverAddress`, `--folderParentID`…) et alias dépréciés `--totpToken/--totpOffset` (Duration) | cli/cli/root.rs |
| CLI-7 | Config : chemin et clés Go (`go-passbolt-cli.toml`, camelCase), chmod 0600, erreurs de parsing avalées, `mfa_retrys=0` par défaut | cli/config.rs:78-96, main.rs:27 |
| CLI-8 | Variables d'environnement : Go sans préfixe (`SERVERADDRESS`…) ; le séparateur `_` casse `PASSBOLT_SERVER_VERIFY_TOKEN` | cli/config.rs:96 |
| CLI-9 | JSON de `list` et `get` brut (struct SDK, metadata chiffrées) au lieu des sorties dédiées de Go | cli/main.rs:459-664 |
| CLI-10 | Alias de commandes (ls, search, new, rm, resources, permission…) | cli/cli/root.rs:106-149 |

## P2 — CLI : compatibilité go-passbolt-cli

| # | Ticket | Preuves Rust |
|---|---|---|
| CLI-11 | `--filter` CEL (avec alias PascalCase, timestamps, maps) | cli/cli/root.rs:305 |
| CLI-12 | Colonnes : noms canoniques plus metadata/secret/expired/expired_at/deleted/resource_type_id/timestamps ; erreur sur colonne inconnue ; déchiffrement des secrets seulement si nécessaire | cli/main.rs:461-522 |
| CLI-13 | `get resource\|folder permission` (sous-commande Go), `-c` respecté, types read/update/owner, JSON compatible | cli/main.rs:330-382 |
| CLI-14 | Sortie de `create` : `ResourceID: <id>` et `{"id":…}` | cli/main.rs:204-262 |
| CLI-15 | `get resource/folder/user/group` : libellés et champs comme Go | cli/main.rs:302-422 |
| CLI-16 | `update group --delete` : booléen qui s'applique à `-u`/`-m` | cli/cli/root.rs:409-423 |
| CLI-17 | `list` : `--group/--resource/--user/--manager` répétables, `-a` admin | cli/cli/root.rs:323-345 |
| CLI-18 | `verify` : mTLS ignoré, message « Verification Enabled » | cli/cli/verify.rs |
| CLI-19 | `configure` : les flags globaux sont masqués ; stocke le chemin de la clé au lieu de son contenu | cli/cli/configure.rs:77-140 |

## P3 — CLI : compatibilité go-passbolt-cli

| # | Ticket | Preuves Rust |
|---|---|---|
| CLI-20 | Chaîne de version avec SHA, date et dirty | cli/cli/root.rs:7 |
| CLI-21 | `gendoc` (une page par commande, erreur sur type inconnu) et `completion` cachés | cli/cli/gendoc.rs |
| CLI-22 | Défauts : `share --type` et `move --folderParentID` requis en Go ; `--json` accepté mais ignoré sur update/delete/share/move ; style de tableau | — |

## P1 — KeePass et exec

| # | Ticket | Preuves Rust |
|---|---|---|
| KP-1 | `--folder-id` inconnu : tout le coffre est exporté | cli/keepass/export.rs:41-50,429-445 |
| EX-1 | `exec` : `process::exit` saute le logout et la sauvegarde des session keys (Go les fait avant le spawn) | cli/cli/exec.rs:59, main.rs:59-61 |

## P2 — KeePass et exec

| # | Ticket | Preuves Rust |
|---|---|---|
| KP-2 | Échecs de déchiffrement masqués : entrée vide comptée comme exportée | export.rs:130-177 |
| KP-3 | URI otpauth mal encodée (label, caractères spéciaux, padding) | export.rs:278-303 |
| KP-4 | Custom fields exportés en champs protégés (dépend de RES-8) | — |
| KP-5 | Flags Go : `-f` = fichier (défaut `passbolt-export.kdbx`), `-p` ; zeroize du mot de passe | cli/cli/export.rs:19-26 |

## P3 — KeePass et exec

| # | Ticket | Preuves Rust |
|---|---|---|
| KP-6 | `--kdbx-version v3\|v4` (la crate keepass 0.6 n'écrit pas v3 : documenter ou changer de KDF) | export.rs:320 |
| KP-7 | Expiration et tags dans l'entrée ; fichier créé en 0600 | export.rs:224-232 |
| EX-2 | Sortie debug, ressource sans mot de passe signalée, code 128+signal, zeroize de la HashMap | cli/cli/exec.rs |

## P1 — Bindings WASM, FFI, napi

| # | Ticket | Preuves Rust |
|---|---|---|
| BND-1 | Métadonnées v5 non exposées : nom vide pour les ressources v5 | ffi/types.rs:36, wasm/lib.rs:94-112 |
| BND-2 | MFA impossible en WASM ; en FFI, uniquement TOTP non interactif avec offset 0 | wasm/lib.rs:58-61, ffi/lib.rs:103-109 |

## P2 — Bindings WASM, FFI, napi

| # | Ticket | Preuves Rust |
|---|---|---|
| BND-3 | Aucune opération d'écriture exposée (create/update/share/move, users, groups…) | — |
| BND-4 | API WASM et FFI incohérentes (getUser, getGroup, deleteFolder, folderTree, signatures différentes) | — |
| BND-5 | Erreurs JS sans code (`AUTH_FAILED`, `MFA_REQUIRED`…) | wasm/lib.rs:22-24 |
| BND-6 | Créer la crate `passbolt-napi` (Phase 3 de la roadmap) | Cargo.toml:2 |

## P3 — Bindings WASM, FFI, napi

| # | Ticket | Preuves Rust |
|---|---|---|
| BND-7 | Passphrase en Uint8Array avec zeroize ; mTLS en FFI ; profil release WASM (`opt-level=s`, wasm-opt) | — |

## Tests et CI

| # | Ticket | Prio |
|---|---|---|
| CI-1 | Pipeline CI : fmt, clippy -D warnings, test, build wasm32, build ffi, cargo-deny/audit ; vérifier `unsafe_code=deny` avec uniffi/napi | P1 |
| TST-1 | Harness d'intégration Passbolt dockerisé (testcontainers) avec v5 activé et scénarios CLI (trycmd) | P1 |
| TST-2 | Aller-retour KeePass (export puis relecture avec la crate keepass) | P1 |
| TST-3 | Tests exec avec mock HTTP | P2 |
| TST-4 | Fuzzing (filtres, expiry, base32/otpauth, UUID) | P2 |
| TST-5 | Test de dérive des schémas de resource types | P2 |
| TST-6 | Tests des bindings (wasm-bindgen-test, smoke test Python/Kotlin) | P2 |
| TST-7 | Benchmarks criterion (decrypt batch, export) | P3 |
| CI-2 | Hooks pre-commit/pre-push (équivalent lefthook) | P3 |

## Licence, en-têtes, README

| # | Ticket | Prio |
|---|---|---|
| LIC-1 | ✅ AGPL-3.0-or-later retenue, comme l'annonçait [sdk-specs/README.md](./sdk-specs/README.md), alors que les 4 Cargo.toml déclaraient MIT | P1 |
| LIC-2 | ✅ Ajouter un fichier LICENSE à la racine | P1 |
| LIC-3 | ✅ En-tête Passbolt dans les fichiers .rs (111, legacy `src/` inclus) | P2 |
| LIC-4 | Script prêt (`scripts/license-headers.sh`, sort en 1 si un en-tête manque) ; reste à le brancher en CI ou en hook | P3 |
| DOC-1 | ✅ README au format Passbolt (bannière, License et clause de marque, About, Credits) | P2 |
| DOC-2 | README : ✅ URL `yourorg` corrigée (remote actuel `scadra/passbolt-rust`) ; reste la section API Compatibility (version minimale testée) | P2 |
| DOC-3 | README : section « Différences avec go-passbolt-cli » et « Ce que Rust a en plus » (`--proxy`, `get totp`, `--totp-*`, `--search`, `--folder-id`, hiérarchie KeePass, pwned, tags, password-expiry CRUD) | P2 |
| DOC-4 | README par crate et métadonnées repository/homepage/authors | P3 |
| DOC-5 | ✅ CHANGELOG.md, SECURITY.md, CONTRIBUTING.md et modèles d'issue / PR `.github/` | P3 |

## Bugs repérés côté Go (à remonter en amont)

- metadatakey.go:137 : panic si la liste de clés est vide.
- metadatakey.go:140 : déréférence d'un UserID nil.
- SetTrustedMetadatakeyFingerprint ignore signTime (metadatakey.go:82-84), l'anti-rollback n'est donc jamais actif.
