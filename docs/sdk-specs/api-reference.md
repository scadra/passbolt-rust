# API Reference

## Event-to-SDK Method Mapping

This document maps every JS event topic from the browser extension's 39 event files to the proposed Rust SDK method.

### Legend

- **JS Event**: The `passbolt.*` topic string registered in the event files
- **SDK Method**: The proposed Rust SDK method call
- **Module**: Which SDK module handles this
- **Notes**: Migration notes or special handling

---

## Auth Events (`authEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.auth.login` | `sdk.auth().login(params)` | GPG challenge-response |
| `passbolt.auth.logout` | `sdk.auth().logout()` | Clears session + caches |
| `passbolt.auth.check-status` | `sdk.auth().check_status()` | Returns `AuthStatus` |
| `passbolt.auth.verify-passphrase` | `sdk.auth().verify_passphrase(passphrase)` | |
| `passbolt.auth.verify-server-key` | `sdk.auth().verify_server_key()` | |
| `passbolt.auth.get-server-key` | `sdk.auth().get_server_key()` | |
| `passbolt.auth.replace-server-key` | `sdk.auth().replace_server_key(key)` | Admin only |
| `passbolt.auth.get-csrf-token` | `sdk.auth().get_csrf_token()` | |
| `passbolt.auth.is-mfa-required` | `sdk.mfa().is_required()` | |
| `passbolt.auth.request-help-credentials-lost` | `sdk.auth().request_help_credentials_lost()` | |
| `passbolt.auth.post-login-redirect` | N/A (UI concern) | Browser-specific redirect |
| `passbolt.auth.post-login-redirect-to-admin-workspace` | N/A (UI concern) | Browser-specific redirect |

## Resource Events (`resourceEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.resources.create` | `sdk.resources().create(params)` | |
| `passbolt.resources.update` | `sdk.resources().update(id, params)` | |
| `passbolt.resources.delete-all` | `sdk.resources().delete_all(ids)` | |
| `passbolt.resources.find-details` | `sdk.resources().find_details(id)` | |
| `passbolt.resources.find-all-by-ids-for-display-permissions` | `sdk.resources().find_by_ids(ids)` | With permissions contain |
| `passbolt.resources.find-all-ids-by-is-shared-with-group` | `sdk.sharing().find_resources_shared_with_group(group_id)` | |
| `passbolt.resources.move-by-ids` | `sdk.resources().move_to_folder(ids, folder_id)` | |
| `passbolt.resources.update-local-storage` | `sdk.resources().update_local_storage()` | |
| `passbolt.resources.update-local-storage-by-folder-parent-id` | `sdk.resources().update_local_storage()` | Merged into single sync |
| `passbolt.resources.set-expiration-date` | `sdk.resources().set_expiration_date(id, date)` | |
| `passbolt.resources.get-grid-setting` | N/A (UI concern) | Grid display settings |
| `passbolt.resources.set-grid-setting` | N/A (UI concern) | Grid display settings |
| `passbolt.resources.reset-grid-setting` | N/A (UI concern) | Grid display settings |

## Secret Events (`secretEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.secret.find-by-resource-id` | `sdk.secrets().find_and_decrypt(resource_id, passphrase)` | |

## Folder Events (`folderEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.folders.create` | `sdk.folders().create(params)` | |
| `passbolt.folders.update` | `sdk.folders().update(id, name)` | |
| `passbolt.folders.delete` | `sdk.folders().delete(id, cascade)` | |
| `passbolt.folders.find-details` | `sdk.folders().find_details(id)` | |
| `passbolt.folders.move-by-id` | `sdk.folders().move_to(id, parent_id, passphrase)` | |
| `passbolt.folders.update-local-storage` | `sdk.folders().update_local_storage()` | |

## Share Events (`shareEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.share.resources.save` | `sdk.sharing().share_resources(ids, changes, passphrase)` | |
| `passbolt.share.folders.save` | `sdk.sharing().share_folder(id, changes, passphrase)` | |
| `passbolt.share.search-aros` | `sdk.sharing().search_aros(search)` | |
| `passbolt.share.get-folders` | `sdk.folders().find_details(id)` | Returns folder with permissions |

## Permission Events (`permissionEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.permissions.find-aco-permissions-for-display` | `sdk.sharing().find_permissions(aco_type, aco_id)` | |

## Favorite Events (in `resourceEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.favorite.add` | `sdk.resources().add_favorite(id)` | |
| `passbolt.favorite.delete` | `sdk.resources().remove_favorite(id)` | |

## User Events (`userEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.users.get-all` | `sdk.users().find_all(options)` | |
| `passbolt.users.find-logged-in-user` | `sdk.users().find_logged_in_user()` | |
| `passbolt.users.create` | `sdk.users().create(params)` | Admin |
| `passbolt.users.update` | `sdk.users().update(id, params)` | |
| `passbolt.users.update-avatar` | `sdk.users().update_avatar(id, data)` | |
| `passbolt.users.delete` | `sdk.users().delete(id)` | Admin |
| `passbolt.users.delete-dry-run` | `sdk.users().delete_dry_run(id)` | Admin |
| `passbolt.users.resend-invite` | `sdk.users().resend_invite(id)` | Admin |
| `passbolt.users.update-security-token` | `sdk.users().update_security_token(token)` | |
| `passbolt.users.update-local-storage` | `sdk.users().update_local_storage()` | |
| `passbolt.user.update-private-key` | `sdk.users().update_private_key(key)` | |

## Group Events (`groupEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.groups.create` | `sdk.groups().create(params)` | |
| `passbolt.groups.update` | `sdk.groups().update(id, params, passphrase)` | |
| `passbolt.groups.delete` | `sdk.groups().delete(id)` | |
| `passbolt.groups.delete-dry-run` | `sdk.groups().delete_dry_run(id)` | |
| `passbolt.groups.find-my-groups` | `sdk.groups().find_my_groups()` | |
| `passbolt.groups.update-local-storage` | `sdk.groups().update_local_storage()` | |

## Keyring Events (`keyringEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.keyring.get-public-key-info-by-user` | `sdk.crypto().keyring().find_public(user_id)` | |
| `passbolt.keyring.get-key-info` | `sdk.crypto().get_key_info(armored_key)` | |
| `passbolt.keyring.get-private-key` | `sdk.crypto().keyring().find_private()` | |
| `passbolt.keyring.download-my-public-key` | `sdk.crypto().keyring().find_public(my_id)` | Returns armored key |
| `passbolt.keyring.download-my-private-key` | `sdk.crypto().keyring().find_private()` | Returns armored key |
| `passbolt.keyring.private.checkpassphrase` | `sdk.crypto().check_passphrase(key, passphrase)` | |

## Comment Events (`commentEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.comments.find-all-by-resource` | `sdk.comments().find_all_by_resource(id)` | |
| `passbolt.comments.create` | `sdk.comments().create(resource_id, content, parent_id)` | |
| `passbolt.comments.delete` | `sdk.comments().delete(id)` | |

## Tag Events (in event handlers)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.tags.find-all` | `sdk.tags().find_all()` | |
| `passbolt.tags.add-resources-tag` | `sdk.tags().add_to_resource(resource_id, slug)` | |
| `passbolt.tags.update-resource-tags` | `sdk.tags().update_resource_tags(resource_id, tags)` | |
| `passbolt.tags.update` | `sdk.tags().update(id, slug)` | |
| `passbolt.tags.delete` | `sdk.tags().delete(id)` | |

## Role Events (`roleEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.role.get-all` | `sdk.roles().get_all()` | |
| `passbolt.role.update-local-storage` | `sdk.roles().update_local_storage()` | |
| `passbolt.rbacs.find-me` | `sdk.rbac().find_me()` | |

## Metadata Events (in event handlers)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.metadata.find-all-non-deleted-metadata-keys` | `sdk.metadata().find_all_metadata_keys()` | |
| `passbolt.metadata.find-metadata-keys-settings` | `sdk.metadata().find_metadata_keys_settings()` | |
| `passbolt.metadata.find-metadata-types-settings` | `sdk.metadata().find_metadata_types_settings()` | |
| `passbolt.metadata.get-or-find-metadata-keys-settings` | `sdk.metadata().get_or_find_metadata_keys_settings()` | Cache-first |
| `passbolt.metadata.get-or-find-metadata-types-settings` | `sdk.metadata().get_or_find_metadata_types_settings()` | Cache-first |
| `passbolt.metadata.save-metadata-keys-settings` | `sdk.metadata().save_metadata_keys_settings(s)` | Admin |
| `passbolt.metadata.save-metadata-types-settings` | `sdk.metadata().save_metadata_types_settings(s)` | Admin |
| `passbolt.metadata.generate-metadata-key` | `sdk.metadata().generate_metadata_key()` | |
| `passbolt.metadata.create-key` | `sdk.metadata().create_key(passphrase)` | |
| `passbolt.metadata.rotate-metadata-key` | `sdk.metadata().rotate_key(passphrase, progress)` | Long-running |
| `passbolt.metadata.resume-rotate-metadata-key` | `sdk.metadata().resume_rotate_key(passphrase, progress)` | |
| `passbolt.metadata.enable` | `sdk.metadata().enable_for_existing_instance(pp, progress)` | Admin |
| `passbolt.metadata.enable-encrypted-metadata-for-existing-instance` | `sdk.metadata().enable_for_existing_instance(pp, progress)` | |
| `passbolt.metadata.keep-cleartext-metadata-for-existing-instance` | `sdk.metadata().keep_cleartext_for_existing_instance()` | |
| `passbolt.metadata.share-missing-metadata-private-keys-with-user` | `sdk.metadata().share_private_key_with_user(key_id, user_id, pp)` | |
| `passbolt.metadata.find-getting-started-settings` | `sdk.metadata().find_getting_started_settings()` | |
| `passbolt.metadata.find-setup-settings` | `sdk.metadata().find_setup_settings()` | |

## MFA Events (`multiFactorAuthenticationEvents.js`, `mfaEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.mfa-setup.get-totp-code` | `sdk.mfa().get_totp_setup_code()` | |
| `passbolt.mfa-setup.verify-totp-code` | `sdk.mfa().verify_totp(code)` | |
| `passbolt.mfa-setup.verify-yubikey-code` | `sdk.mfa().verify_yubikey(otp)` | |
| `passbolt.mfa-setup.start-with-duo` | `sdk.mfa().start_duo_setup()` | |
| `passbolt.mfa-setup.verify-provider` | `sdk.mfa().verify_provider(provider, code)` | |
| `passbolt.mfa-setup.remove-provider` | `sdk.mfa().remove_provider(provider)` | Admin |
| `passbolt.mfa-policy.get-policy` | `sdk.mfa().get_policy()` | |
| `passbolt.mfa-policy.get-mfa-settings` | `sdk.mfa().get_settings()` | |
| `passbolt.mfa-policy.has-user-postponed-user-setting-invitation` | `sdk.mfa().has_postponed_invitation()` | |
| `passbolt.mfa-policy.postpone-user-setting-invitation` | `sdk.mfa().postpone_invitation()` | |
| `passbolt.mfa.disable-for-user` | `sdk.mfa().disable_for_user(user_id)` | Admin |

## SSO Events (in auth/SSO event handlers)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.sso.get-current` | `sdk.sso().get_settings()` | |
| `passbolt.sso.get-local-configured-provider` | `sdk.sso().get_local_provider()` | |
| `passbolt.sso.generate-sso-kit` | `sdk.sso().generate_kit(passphrase)` | |
| `passbolt.sso.sign-in` | `sdk.sso().login(provider_token)` | |
| `passbolt.sso.save-draft` | `sdk.sso().save_draft(settings)` | Admin |
| `passbolt.sso.activate-settings` | `sdk.sso().activate(settings)` | Admin |
| `passbolt.sso.delete-settings` | `sdk.sso().delete_settings()` | Admin |
| `passbolt.sso.delete-local-kit` | `sdk.sso().delete_local_kit()` | |
| `passbolt.sso.update-provider-local-kit` | `sdk.sso().update_provider_kit(passphrase)` | |
| `passbolt.sso.dry-run` | `sdk.sso().dry_run(settings)` | Admin |
| `passbolt.sso.has-sso-login-error` | `sdk.sso().has_login_error()` | |
| `passbolt.sso.get-qualified-sso-login-error` | `sdk.sso().get_login_error()` | |

## Config Events (`configEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.config.read` | `sdk.config().get(key)` | |
| `passbolt.config.readAll` | `sdk.config().get_all()` | |
| `passbolt.addon.get-domain` | `sdk.config().server_url()` | |
| `passbolt.addon.get-url` | N/A (browser-specific) | Extension URL |
| `passbolt.addon.get-version` | `sdk.config().version()` | |
| `passbolt.addon.is-configured` | `sdk.config().is_configured()` | |
| `passbolt.addon.check-domain` | `sdk.config().check_domain(url)` | |

## Organization Settings Events (`organizationSettingsEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.organization-settings.get` | `sdk.config().get_organization_settings()` | |

## Password Policy Events (`passwordPoliciesEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.password-policies.get` | `sdk.config().get_password_policies()` | |
| `passbolt.password-policies.get-admin-settings` | `sdk.config().get_password_policies_admin()` | Admin |
| `passbolt.password-policies.save` | `sdk.config().save_password_policies(settings)` | Admin |

## Password Expiry Events

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.password-expiry.get-or-find` | `sdk.password_expiry().get_settings()` | |
| `passbolt.password-expiry.save` | `sdk.password_expiry().save_settings(settings)` | Admin |
| `passbolt.password-expiry.delete` | `sdk.password_expiry().delete_settings()` | Admin |

## Pwned Password Events (`pownedPasswordEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.secrets.powned-password` | `sdk.secrets().check_pwned(password)` | |

## Resource Type Events (`resourceTypeEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.resource-type.get-or-find-all` | `sdk.resource_types().get_or_find_all()` | |
| `passbolt.resource-type.find-all-by-deleted-and-non-deleted` | `sdk.resource_types().find_all()` | |
| `passbolt.resource-types.update-all-deleted-status` | `sdk.resource_types().update_deleted_status(changes)` | Admin |

## Action Log Events (`actionLogEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.actionlogs.find-all-for` | `sdk.action_logs().find_all_for(entity_id)` | |

## Account Events (`accountEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.account.get` | `sdk.config().get_account()` | |

## Account Recovery Events (`accountRecoveryEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.account-recovery.get-organization-policy` | `sdk.account_recovery().get_policy()` | |
| `passbolt.account-recovery.save-user-settings` | `sdk.account_recovery().save_user_settings(s)` | |
| `passbolt.account-recovery.get-user-requests` | `sdk.account_recovery().get_user_requests()` | |
| `passbolt.account-recovery.get-request` | `sdk.account_recovery().get_request(id)` | |
| `passbolt.account-recovery.recover-account` | `sdk.account_recovery().recover(params)` | |
| `passbolt.account-recovery.get-account` | `sdk.account_recovery().get_account()` | |
| `passbolt.account-recovery.verify-passphrase` | `sdk.auth().verify_passphrase(pp)` | |
| `passbolt.account-recovery.sign-in` | `sdk.auth().login(params)` | |
| `passbolt.account-recovery.continue` | `sdk.account_recovery().continue_recovery()` | |
| `passbolt.account-recovery.generate-organization-key` | `sdk.account_recovery().generate_org_key(params)` | Admin |
| `passbolt.account-recovery.download-organization-generated-key` | `sdk.account_recovery().download_org_key()` | Admin |
| `passbolt.account-recovery.download-recovery-kit` | `sdk.account_recovery().download_recovery_kit()` | |
| `passbolt.account-recovery.has-user-postponed-user-setting-invitation` | `sdk.account_recovery().has_postponed_invitation()` | |
| `passbolt.account-recovery.postpone-user-setting-invitation` | `sdk.account_recovery().postpone_invitation()` | |
| `passbolt.account-recovery.request-help-credentials-lost` | `sdk.auth().request_help_credentials_lost()` | |

## Setup Events (`setupEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.setup.start` | `sdk.setup().start()` | |
| `passbolt.setup.generate-key` | `sdk.crypto().generate_key(params)` | |
| `passbolt.setup.import-key` | `sdk.setup().import_key(armored)` | |
| `passbolt.setup.validate-private-key` | `sdk.crypto().get_key_info(armored)` | |
| `passbolt.setup.verify-passphrase` | `sdk.crypto().check_passphrase(key, pp)` | |
| `passbolt.setup.set-security-token` | `sdk.setup().set_security_token(token)` | |
| `passbolt.setup.complete` | `sdk.setup().complete()` | |
| `passbolt.setup.sign-in` | `sdk.auth().login(params)` | |
| `passbolt.setup.download-recovery-kit` | `sdk.setup().download_recovery_kit()` | |
| `passbolt.setup.get-and-init-locale` | `sdk.config().get_locale()` | |
| `passbolt.setup.update-locale` | `sdk.config().update_locale(locale)` | |
| `passbolt.setup.is-first-install` | `sdk.setup().is_first_install()` | |
| `passbolt.setup.get-account-recovery-organization-policy` | `sdk.account_recovery().get_policy()` | |
| `passbolt.setup.set-account-recovery-user-setting` | `sdk.account_recovery().save_user_settings(s)` | |
| `passbolt.setup.get-user-passphrase-policies` | `sdk.config().get_passphrase_policies()` | |

## Recover Events (`recoverEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.recover.start` | `sdk.recover().start()` | |
| `passbolt.recover.import-key` | `sdk.recover().import_key(armored)` | |
| `passbolt.recover.validate-private-key` | `sdk.crypto().get_key_info(armored)` | |
| `passbolt.recover.verify-passphrase` | `sdk.crypto().check_passphrase(key, pp)` | |
| `passbolt.recover.set-security-token` | `sdk.recover().set_security_token(token)` | |
| `passbolt.recover.complete` | `sdk.recover().complete()` | |
| `passbolt.recover.sign-in` | `sdk.auth().login(params)` | |
| `passbolt.recover.first-install` | `sdk.recover().is_first_install()` | |
| `passbolt.recover.lost-passphrase-case` | `sdk.recover().lost_passphrase_case()` | |
| `passbolt.recover.request-help-credentials-lost` | `sdk.auth().request_help_credentials_lost()` | |
| `passbolt.recover.has-user-enabled-account-recovery` | `sdk.account_recovery().has_user_enabled()` | |
| `passbolt.recover.initiate-account-recovery-request` | `sdk.account_recovery().initiate_request()` | |
| `passbolt.recover.generate-account-recovery-request-key` | `sdk.account_recovery().generate_request_key(params)` | |
| `passbolt.recover.get-user-passphrase-policies` | `sdk.config().get_passphrase_policies()` | |

## Locale Events (`localeEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.locale.get` | `sdk.config().get_locale()` | |
| `passbolt.locale.update-user-locale` | `sdk.config().update_locale(locale)` | |

## Theme Events (`themeEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.themes.find-all` | `sdk.config().find_themes()` | |
| `passbolt.themes.change` | `sdk.config().change_theme(name)` | |

## Import/Export Events

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.import-resources.import-file` | `sdk.import_export().import_file(data, format)` | |
| `passbolt.export-resources.export-to-file` | `sdk.import_export().export_to_file(ids, format)` | |
| `passbolt.export-policies.get` | `sdk.config().get_export_policies()` | |

## Mobile Events (`mobileEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.mobile.transfer.create` | `sdk.mobile().create_transfer()` | |
| `passbolt.mobile.transfer.get` | `sdk.mobile().get_transfer(id)` | |
| `passbolt.mobile.transfer.update` | `sdk.mobile().update_transfer(id, data)` | |
| `passbolt.desktop.export-account` | `sdk.mobile().export_account()` | |

## Remember Me Events (`rememberMeEvents.js`)

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.remember-me.get-user-latest-choice` | `sdk.config().get_remember_me_choice()` | |

## Passphrase Policy Events

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.user-passphrase-policies.find` | `sdk.config().get_passphrase_policies()` | |
| `passbolt.user-passphrase-policies.save` | `sdk.config().save_passphrase_policies(s)` | Admin |

## Secret Revision Events

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.secret-revisions.find-all-by-resource-id-for-display` | `sdk.secret_revisions().find_all_by_resource_id(id)` | |
| `passbolt.secret-revisions.find-settings` | `sdk.secret_revisions().find_settings()` | |
| `passbolt.secret-revisions.save-settings` | `sdk.secret_revisions().save_settings(s)` | Admin |
| `passbolt.secret-revisions.delete-settings` | `sdk.secret_revisions().delete_settings()` | Admin |

## Subscription Events

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.subscription.get` | `sdk.config().get_subscription()` | Admin |
| `passbolt.subscription.update` | `sdk.config().update_subscription(key)` | Admin |

## SCIM Events

| JS Event | SDK Method | Notes |
|----------|-----------|-------|
| `passbolt.scim.find-settings` | `sdk.scim().find_settings()` | Admin |
| `passbolt.scim.create-settings` | `sdk.scim().create_settings(s)` | Admin |
| `passbolt.scim.update-settings` | `sdk.scim().update_settings(s)` | Admin |
| `passbolt.scim.disable-settings` | `sdk.scim().disable()` | Admin |

## Browser-Specific Events (Not in SDK)

These events are UI/browser-specific and will not be part of the SDK:

| JS Event | Reason |
|----------|--------|
| `passbolt.port.disconnect` | Browser port management |
| `passbolt.port.generate-id` | Browser port management |
| `passbolt.tab.reload` | Browser tab control |
| `passbolt.tabs.open-*` | Browser tab navigation |
| `passbolt.active-tab.*` | Browser tab queries |
| `passbolt.clipboard.*` | Browser clipboard access |
| `passbolt.quickaccess.*` | Browser extension popup UI |
| `passbolt.in-form-menu.*` | Browser form detection UI |
| `passbolt.in-form-cta.*` | Browser CTA UI |
| `passbolt.web-integration.*` | Browser page integration |
| `passbolt.app.route-changed` | Browser SPA routing |
| `passbolt.extension.*` | Browser extension management |
| `passbolt.safari.*` | Safari-specific |

---

## SDK Entry Point

All methods are accessed through the main `PassboltSdk` struct:

```rust
let sdk = PassboltSdk::builder()
    .server_url("https://passbolt.example.com")
    .transport(transport)
    .storage(storage)
    .build()?;

// Module access
sdk.auth()          // → AuthClient
sdk.mfa()           // → MfaClient
sdk.sso()           // → SsoClient
sdk.crypto()        // → CryptoService
sdk.resources()     // → ResourcesClient
sdk.secrets()       // → SecretsClient
sdk.folders()       // → FoldersClient
sdk.sharing()       // → SharingClient
sdk.users()         // → UsersClient
sdk.groups()        // → GroupsClient
sdk.metadata()      // → MetadataClient
sdk.tags()          // → TagsClient
sdk.comments()      // → CommentsClient
sdk.roles()         // → RolesClient
sdk.rbac()          // → RbacClient
sdk.config()        // → ConfigClient
sdk.import_export() // → ImportExportClient
sdk.action_logs()   // → ActionLogsClient
sdk.setup()            // → SetupClient
sdk.recover()          // → RecoverClient
sdk.account_recovery() // → AccountRecoveryClient
sdk.password_expiry()  // → PasswordExpiryClient
sdk.secret_revisions() // → SecretRevisionsClient
sdk.resource_types()   // → ResourceTypesClient
```

## Statistics

- **Total JS events**: ~190 event topics across 39 files
- **Mapped to SDK methods**: ~155 (business logic)
- **Browser-specific (not in SDK)**: ~35 (UI/browser concerns)
- **SDK modules**: 20+ client types

---

## Complete Method Signatures

This section provides the full Rust signatures for every SDK method, grouped by module. Each entry includes: parameters, return type, error type, and whether the method is async.

### Common Types

These types are used across multiple modules. See [architecture.md](./architecture.md) for `Transport`, `Storage`, `PaginationParams`, `PaginatedResponse`.

```rust
// Re-exported from architecture
pub use crate::{PaginationParams, PaginatedResponse, PaginationInfo};

// Common error wrapper
pub type SdkResult<T> = Result<T, SdkError>;
```

---

### AuthClient

```rust
impl<T: Transport, S: Storage> AuthClient<T, S> {
    /// GPG challenge-response login
    /// Async: Yes | Errors: InvalidPassphrase, ServerVerificationFailed, InvalidTokenFormat, Transport
    pub async fn login(&self, params: LoginParams) -> Result<Session, AuthError>;

    /// Logout and cleanup all session state
    /// Async: Yes | Errors: Transport
    pub async fn logout(&self) -> Result<(), AuthError>;

    /// Check current authentication status
    /// Async: Yes | Errors: Transport
    pub async fn check_status(&self) -> Result<AuthStatus, AuthError>;

    /// Verify the server's GPG key identity
    /// Async: Yes | Errors: ServerVerificationFailed, Transport, Crypto
    pub async fn verify_server_key(&self) -> Result<(), AuthError>;

    /// Validate a passphrase against the stored private key (does not log in)
    /// Async: No (CPU-bound crypto) | Errors: InvalidPassphrase, Crypto
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<(), AuthError>;

    /// Get the server's public PGP key
    /// Async: Yes | Errors: Transport
    pub async fn get_server_key(&self) -> Result<String, AuthError>;

    /// Replace the server's public key (admin only)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn replace_server_key(&self, armored_key: &str) -> Result<(), AuthError>;

    /// Get the current CSRF token
    /// Async: Yes | Errors: SessionExpired, Transport
    pub async fn get_csrf_token(&self) -> Result<String, AuthError>;

    /// Request help for lost credentials (sends email)
    /// Async: Yes | Errors: Transport
    pub async fn request_help_credentials_lost(&self) -> Result<(), AuthError>;
}

pub struct LoginParams {
    pub user_fingerprint: String,
    pub user_private_armored_key: String,
    pub passphrase: String,
    pub remember_me: bool,
}

pub struct AuthStatus {
    pub is_authenticated: bool,
    pub is_mfa_required: bool,
}

pub struct Session {
    pub user_id: Uuid,
    pub csrf_token: String,
}
```

### MfaClient

```rust
impl<T: Transport, S: Storage> MfaClient<T, S> {
    /// Check if MFA verification is required
    /// Async: Yes | Errors: Transport
    pub async fn is_required(&self) -> Result<bool, AuthError>;

    /// Get TOTP setup code (QR code data)
    /// Async: Yes | Errors: Transport
    pub async fn get_totp_setup_code(&self) -> Result<TotpSetup, AuthError>;

    /// Verify a TOTP code
    /// Async: Yes | Errors: InvalidMfaCode, Transport
    pub async fn verify_totp(&self, code: &str) -> Result<(), AuthError>;

    /// Verify a Yubikey OTP
    /// Async: Yes | Errors: InvalidMfaCode, Transport
    pub async fn verify_yubikey(&self, otp: &str) -> Result<(), AuthError>;

    /// Start Duo MFA setup
    /// Async: Yes | Errors: Transport
    pub async fn start_duo_setup(&self) -> Result<DuoSetup, AuthError>;

    /// Verify any MFA provider
    /// Async: Yes | Errors: InvalidMfaCode, Transport
    pub async fn verify_provider(&self, provider: MfaProvider, code: &str) -> Result<(), AuthError>;

    /// Remove an MFA provider (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn remove_provider(&self, provider: MfaProvider) -> Result<(), AuthError>;

    /// Get MFA policy
    /// Async: Yes | Errors: Transport
    pub async fn get_policy(&self) -> Result<MfaPolicy, AuthError>;

    /// Get MFA settings
    /// Async: Yes | Errors: Transport
    pub async fn get_settings(&self) -> Result<MfaSettings, AuthError>;

    /// Check if user has postponed MFA invitation
    /// Async: No | Errors: Storage
    pub fn has_postponed_invitation(&self) -> Result<bool, AuthError>;

    /// Postpone MFA invitation
    /// Async: Yes | Errors: Storage
    pub async fn postpone_invitation(&self) -> Result<(), AuthError>;

    /// Disable MFA for a user (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn disable_for_user(&self, user_id: &Uuid) -> Result<(), AuthError>;
}

pub enum MfaProvider { Totp, Yubikey, Duo }
pub struct TotpSetup { pub qr_code: String, pub secret: String }
pub struct DuoSetup { pub redirect_url: String }
pub struct MfaPolicy { pub policy: String, pub remember_me_for_month: bool }
pub struct MfaSettings { pub providers: Vec<MfaProvider> }
```

### SsoClient

```rust
impl<T: Transport, S: Storage> SsoClient<T, S> {
    /// Get current SSO settings
    /// Async: Yes | Errors: Transport
    pub async fn get_settings(&self) -> Result<SsoSettings, AuthError>;

    /// Get locally configured SSO provider
    /// Async: Yes | Errors: Storage
    pub async fn get_local_provider(&self) -> Result<Option<String>, AuthError>;

    /// Generate SSO kit (encrypt passphrase for SSO recovery)
    /// Async: Yes | Errors: Crypto, Storage
    pub async fn generate_kit(&self, passphrase: &str) -> Result<(), AuthError>;

    /// Login via SSO provider token
    /// Async: Yes | Errors: SsoError, Transport, Crypto
    pub async fn login(&self, provider_token: &str) -> Result<Session, AuthError>;

    /// Save SSO draft settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn save_draft(&self, settings: SsoSettings) -> Result<SsoSettings, AuthError>;

    /// Activate SSO settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn activate(&self, settings: SsoSettings) -> Result<SsoSettings, AuthError>;

    /// Delete SSO settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn delete_settings(&self) -> Result<(), AuthError>;

    /// Delete local SSO kit
    /// Async: Yes | Errors: Storage
    pub async fn delete_local_kit(&self) -> Result<(), AuthError>;

    /// Update provider local kit
    /// Async: Yes | Errors: Crypto, Storage
    pub async fn update_provider_kit(&self, passphrase: &str) -> Result<(), AuthError>;

    /// Dry-run SSO settings (admin)
    /// Async: Yes | Errors: SsoError, Transport
    pub async fn dry_run(&self, settings: SsoSettings) -> Result<(), AuthError>;

    /// Check if there was an SSO login error
    /// Async: No | Errors: Storage
    pub fn has_login_error(&self) -> Result<bool, AuthError>;

    /// Get qualified SSO login error
    /// Async: No | Errors: Storage
    pub fn get_login_error(&self) -> Result<Option<String>, AuthError>;
}

pub struct SsoSettings {
    pub id: Option<Uuid>,
    pub provider: String,  // "azure", "google", "oauth2"
    pub data: serde_json::Value,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
}
```

---

### ResourcesClient

```rust
impl<T: Transport, S: Storage> ResourcesClient<T, S> {
    /// Create a new resource (encrypts secret + optional metadata)
    /// Async: Yes | Errors: ValidationFailed, ResourceTypeNotFound, Crypto, Transport
    pub async fn create(&self, params: CreateResourceParams) -> Result<Resource, ResourceError>;

    /// Find resources with filters, contain, and ordering
    /// Async: Yes | Errors: Transport
    pub async fn find(&self, options: FindResourcesOptions) -> Result<Vec<Resource>, ResourceError>;

    /// Find a single resource by ID with full details
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn find_details(&self, id: &Uuid) -> Result<Resource, ResourceError>;

    /// Get from local cache or fetch from API
    /// Async: Yes | Errors: Transport, Storage
    pub async fn get_or_find(&self, options: FindResourcesOptions) -> Result<Vec<Resource>, ResourceError>;

    /// Update an existing resource (re-encrypts secret for all recipients if secret changes)
    /// Async: Yes | Errors: NotFound, ValidationFailed, Crypto, Transport
    pub async fn update(&self, id: &Uuid, params: UpdateResourceParams) -> Result<Resource, ResourceError>;

    /// Delete a single resource
    /// Async: Yes | Errors: NotFound, InsufficientPermissions, Transport
    pub async fn delete(&self, id: &Uuid) -> Result<(), ResourceError>;

    /// Delete multiple resources
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn delete_all(&self, ids: &[Uuid]) -> Result<(), ResourceError>;

    /// Move resources to a folder (may trigger re-sharing)
    /// Async: Yes | Errors: NotFound, InsufficientPermissions, Transport
    pub async fn move_to_folder(&self, ids: &[Uuid], folder_id: Option<Uuid>) -> Result<(), ResourceError>;

    /// Add a resource to favorites
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn add_favorite(&self, id: &Uuid) -> Result<Favorite, ResourceError>;

    /// Remove a resource from favorites
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn remove_favorite(&self, favorite_id: &Uuid) -> Result<(), ResourceError>;

    /// Sync local storage cache with server
    /// Async: Yes | Errors: Transport, Storage
    pub async fn update_local_storage(&self) -> Result<(), ResourceError>;

    /// Set password expiry date on a resource
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn set_expiration_date(&self, id: &Uuid, expiry: Option<DateTime<Utc>>) -> Result<(), ResourceError>;
}
```

See [resources.md](./modules/resources.md) for `CreateResourceParams`, `UpdateResourceParams`, `FindResourcesOptions`, `Resource`, `ResourceContain`, `ResourceFilters`, `ResourceOrder`, `SecretData`, `TotpData`.

---

### SecretsClient

```rust
impl<T: Transport, S: Storage> SecretsClient<T, S> {
    /// Fetch the encrypted secret for a resource (does not decrypt)
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn find_by_resource_id(&self, resource_id: &Uuid) -> Result<EncryptedSecret, SecretError>;

    /// Fetch and decrypt the secret for a resource
    /// Async: Yes | Errors: NotFound, Crypto, ParseFailed, Transport
    pub async fn find_and_decrypt(&self, resource_id: &Uuid, passphrase: &str) -> Result<SecretData, SecretError>;

    /// Decrypt an already-fetched secret
    /// Async: No (CPU-bound) | Errors: Crypto, ParseFailed, InvalidSchema
    pub fn decrypt(&self, encrypted: &EncryptedSecret, resource_type_id: &Uuid, passphrase: &str) -> Result<SecretData, SecretError>;

    /// Bulk decrypt multiple secrets (unlocks private key once)
    /// Async: No (CPU-bound) | Errors: Crypto, ParseFailed
    pub fn decrypt_all(&self, secrets: &[(EncryptedSecret, Uuid)], passphrase: &str) -> Result<Vec<SecretData>, SecretError>;

    /// Encrypt a secret for multiple recipients
    /// Async: No (CPU-bound) | Errors: Crypto
    pub fn encrypt_for_recipients(&self, secret: &SecretData, recipient_keys: &[(Uuid, PublicKey)], passphrase: &str) -> Result<Vec<EncryptedSecretForUser>, SecretError>;

    /// Check if a password has been exposed in data breaches (HIBP k-anonymity)
    /// Async: Yes | Errors: Transport
    pub async fn check_pwned(&self, password: &str) -> Result<u64, SecretError>;
}
```

See [secrets.md](./modules/secrets.md) for `EncryptedSecret`, `EncryptedSecretForUser`, `SecretData`, `PasswordExpirySettings`, `SecretRevision`.

---

### FoldersClient

```rust
impl<T: Transport, S: Storage> FoldersClient<T, S> {
    /// Create a new folder (inherits parent permissions if in shared folder)
    /// Async: Yes | Errors: ValidationFailed, Transport
    pub async fn create(&self, params: CreateFolderParams) -> Result<Folder, FolderError>;

    /// Find folder details by ID (with permissions, children)
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn find_details(&self, id: &Uuid) -> Result<Folder, FolderError>;

    /// Update a folder's name
    /// Async: Yes | Errors: NotFound, ValidationFailed, Transport
    pub async fn update(&self, id: &Uuid, name: &str) -> Result<Folder, FolderError>;

    /// Delete a folder (with optional cascade to children)
    /// Async: Yes | Errors: NotFound, InsufficientPermissions, Transport
    pub async fn delete(&self, id: &Uuid, cascade: bool) -> Result<(), FolderError>;

    /// Move a folder (may trigger permission recalculation + secret re-encryption)
    /// Async: Yes | Errors: NotFound, CircularReference, InsufficientPermissions, Sharing, Crypto, Transport
    pub async fn move_to(&self, id: &Uuid, folder_parent_id: Option<Uuid>, passphrase: &str) -> Result<(), FolderError>;

    /// Sync local folder cache with server
    /// Async: Yes | Errors: Transport, Storage
    pub async fn update_local_storage(&self) -> Result<(), FolderError>;

    /// Build a tree structure from a flat list of folders
    /// Async: No (pure computation) | Errors: None (infallible)
    pub fn build_tree(&self, folders: &[Folder]) -> Vec<FolderTreeNode>;
}
```

See [folders.md](./modules/folders.md) for `CreateFolderParams`, `Folder`, `FolderTreeNode`.

---

### SharingClient

```rust
impl<T: Transport, S: Storage> SharingClient<T, S> {
    /// Share resources with new/changed permissions (handles secret re-encryption)
    /// Async: Yes | Errors: MissingPublicKey, NoOwnerRemaining, EncryptionFailed, Crypto, Transport
    pub async fn share_resources(&self, resource_ids: &[Uuid], permission_changes: PermissionChanges, passphrase: &str) -> Result<(), SharingError>;

    /// Share a folder (cascades to all contained resources/subfolders)
    /// Async: Yes | Errors: MissingPublicKey, NoOwnerRemaining, EncryptionFailed, Crypto, Transport
    pub async fn share_folder(&self, folder_id: &Uuid, permission_changes: PermissionChanges, passphrase: &str) -> Result<(), SharingError>;

    /// Search for users and groups to share with (autocomplete)
    /// Async: Yes | Errors: Transport
    pub async fn search_aros(&self, search: &str) -> Result<Vec<Aro>, SharingError>;

    /// Get all permissions for a resource or folder
    /// Async: Yes | Errors: Transport
    pub async fn find_permissions(&self, aco_type: AcoType, aco_id: &Uuid) -> Result<Vec<Permission>, SharingError>;

    /// Get IDs of all resources shared with a group
    /// Async: Yes | Errors: Transport
    pub async fn find_resources_shared_with_group(&self, group_id: &Uuid) -> Result<Vec<Uuid>, SharingError>;
}
```

See [sharing.md](./modules/sharing.md) for `Permission`, `PermissionType`, `PermissionChanges`, `PermissionChange`, `AcoType`, `AroType`, `Aro`, `UserAro`, `GroupAro`.

---

### UsersClient

```rust
impl<T: Transport, S: Storage> UsersClient<T, S> {
    /// Get all users with optional contain/filter
    /// Async: Yes | Errors: Transport
    pub async fn find_all(&self, options: FindUsersOptions) -> Result<Vec<User>, UserError>;

    /// Get the currently authenticated user
    /// Async: Yes | Errors: SessionExpired, Transport
    pub async fn find_logged_in_user(&self) -> Result<User, UserError>;

    /// Create a new user (admin only, sends invitation email)
    /// Async: Yes | Errors: ValidationFailed, InsufficientPermissions, Transport
    pub async fn create(&self, params: CreateUserParams) -> Result<User, UserError>;

    /// Update a user's profile or role
    /// Async: Yes | Errors: NotFound, ValidationFailed, Transport
    pub async fn update(&self, id: &Uuid, params: UpdateUserParams) -> Result<User, UserError>;

    /// Update a user's avatar (multipart upload)
    /// Async: Yes | Errors: NotFound, ValidationFailed, Transport
    pub async fn update_avatar(&self, id: &Uuid, image_data: &[u8]) -> Result<(), UserError>;

    /// Delete a user (admin only)
    /// Async: Yes | Errors: NotFound, SoleOwnerConflict, InsufficientPermissions, Transport
    pub async fn delete(&self, id: &Uuid) -> Result<(), UserError>;

    /// Dry-run delete: check impact before actual deletion
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn delete_dry_run(&self, id: &Uuid) -> Result<DeleteDryRun, UserError>;

    /// Resend invitation email (admin only)
    /// Async: Yes | Errors: NotFound, InsufficientPermissions, Transport
    pub async fn resend_invite(&self, id: &Uuid) -> Result<(), UserError>;

    /// Update the visual security token
    /// Async: Yes | Errors: ValidationFailed, Transport
    pub async fn update_security_token(&self, token: SecurityToken) -> Result<(), UserError>;

    /// Sync local user cache with server
    /// Async: Yes | Errors: Transport, Storage
    pub async fn update_local_storage(&self) -> Result<(), UserError>;

    /// Update user's private key (key rotation)
    /// Async: Yes | Errors: Transport
    pub async fn update_private_key(&self, armored_key: &str) -> Result<(), UserError>;
}
```

See [users.md](./modules/users.md) for `FindUsersOptions`, `UserContain`, `UserFilters`, `User`, `UserProfile`, `Avatar`, `Role`, `SecurityToken`, `CreateUserParams`, `UpdateUserParams`, `DeleteDryRun`, `RbacPermissions`.

---

### GroupsClient

```rust
impl<T: Transport, S: Storage> GroupsClient<T, S> {
    /// Create a new group (at least one admin member required)
    /// Async: Yes | Errors: ValidationFailed, Transport
    pub async fn create(&self, params: CreateGroupParams) -> Result<Group, GroupError>;

    /// Update a group (name/members). Adding members triggers re-encryption.
    /// Async: Yes | Errors: NotFound, NoAdminRemaining, ValidationFailed, Crypto, Transport
    pub async fn update(&self, id: &Uuid, params: UpdateGroupParams, passphrase: &str) -> Result<Group, GroupError>;

    /// Delete a group
    /// Async: Yes | Errors: NotFound, SoleAccessorConflict, Transport
    pub async fn delete(&self, id: &Uuid) -> Result<(), GroupError>;

    /// Dry-run delete: check if resources would become orphaned
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn delete_dry_run(&self, id: &Uuid) -> Result<GroupDeleteDryRun, GroupError>;

    /// Find all groups
    /// Async: Yes | Errors: Transport
    pub async fn find_all(&self) -> Result<Vec<Group>, GroupError>;

    /// Find groups the current user belongs to
    /// Async: Yes | Errors: Transport
    pub async fn find_my_groups(&self) -> Result<Vec<Group>, GroupError>;

    /// Sync local group cache with server
    /// Async: Yes | Errors: Transport, Storage
    pub async fn update_local_storage(&self) -> Result<(), GroupError>;
}
```

See [groups.md](./modules/groups.md) for `Group`, `GroupUser`, `CreateGroupParams`, `UpdateGroupParams`, `GroupMemberParam`, `GroupMemberUpdateParam`, `GroupDeleteDryRun`.

---

### MetadataClient

```rust
impl<T: Transport, S: Storage> MetadataClient<T, S> {
    // --- Key Management ---

    /// Find all non-deleted metadata keys
    /// Async: Yes | Errors: Transport
    pub async fn find_all_metadata_keys(&self) -> Result<Vec<MetadataKey>, MetadataError>;

    /// Get or find metadata keys (cache-first)
    /// Async: Yes | Errors: Transport, Storage
    pub async fn get_or_find_metadata_keys(&self) -> Result<Vec<MetadataKey>, MetadataError>;

    /// Generate a new metadata key pair (does not save)
    /// Async: No (CPU-bound) | Errors: Crypto
    pub fn generate_metadata_key(&self) -> Result<MetadataKey, MetadataError>;

    /// Create and save a new metadata key on the server
    /// Async: Yes | Errors: Crypto, Transport
    pub async fn create_key(&self, passphrase: &str) -> Result<MetadataKey, MetadataError>;

    /// Share a metadata private key with a user
    /// Async: Yes | Errors: KeyNotFound, Crypto, Transport
    pub async fn share_private_key_with_user(&self, metadata_key_id: &Uuid, user_id: &Uuid, passphrase: &str) -> Result<(), MetadataError>;

    // --- Encrypt/Decrypt ---

    /// Encrypt metadata for a resource (returns armored PGP message)
    /// Async: No (CPU-bound) | Errors: Crypto, InvalidFormat
    pub fn encrypt_metadata(&self, metadata: &ResourceMetadata, key: &MetadataEncryptionKey, signing_key: &DecryptedPrivateKey) -> Result<String, MetadataError>;

    /// Decrypt metadata from a resource
    /// Async: No (CPU-bound) | Errors: DecryptionFailed, InvalidFormat, PrivateKeyNotAvailable, Crypto
    pub fn decrypt_metadata(&self, encrypted_metadata: &str, key_type: MetadataKeyType, metadata_key_id: Option<&Uuid>, passphrase: &str) -> Result<ResourceMetadata, MetadataError>;

    // --- Key Rotation ---

    /// Rotate the metadata key (long-running, reports progress)
    /// Async: Yes | Errors: RotationInProgress, Crypto, Transport
    pub async fn rotate_key(&self, passphrase: &str, progress: &dyn ProgressReporter) -> Result<(), MetadataError>;

    /// Resume an interrupted key rotation
    /// Async: Yes | Errors: Crypto, Transport
    pub async fn resume_rotate_key(&self, passphrase: &str, progress: &dyn ProgressReporter) -> Result<(), MetadataError>;

    // --- Settings ---

    /// Get metadata types settings
    /// Async: Yes | Errors: Transport
    pub async fn find_metadata_types_settings(&self) -> Result<MetadataTypesSettings, MetadataError>;

    /// Get or find metadata types settings (cache-first)
    /// Async: Yes | Errors: Transport, Storage
    pub async fn get_or_find_metadata_types_settings(&self) -> Result<MetadataTypesSettings, MetadataError>;

    /// Save metadata types settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn save_metadata_types_settings(&self, settings: MetadataTypesSettings) -> Result<(), MetadataError>;

    /// Get metadata keys settings
    /// Async: Yes | Errors: Transport
    pub async fn find_metadata_keys_settings(&self) -> Result<MetadataKeysSettings, MetadataError>;

    /// Get or find metadata keys settings (cache-first)
    /// Async: Yes | Errors: Transport, Storage
    pub async fn get_or_find_metadata_keys_settings(&self) -> Result<MetadataKeysSettings, MetadataError>;

    /// Save metadata keys settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn save_metadata_keys_settings(&self, settings: MetadataKeysSettings) -> Result<(), MetadataError>;

    // --- Migration ---

    /// Enable encrypted metadata for an existing instance (admin, long-running)
    /// Async: Yes | Errors: Crypto, Transport
    pub async fn enable_for_existing_instance(&self, passphrase: &str, progress: &dyn ProgressReporter) -> Result<(), MetadataError>;

    /// Keep cleartext metadata for existing instance (opt-out)
    /// Async: Yes | Errors: Transport
    pub async fn keep_cleartext_for_existing_instance(&self) -> Result<(), MetadataError>;

    /// Find getting-started settings
    /// Async: Yes | Errors: Transport
    pub async fn find_getting_started_settings(&self) -> Result<serde_json::Value, MetadataError>;

    /// Find setup settings
    /// Async: Yes | Errors: Transport
    pub async fn find_setup_settings(&self) -> Result<serde_json::Value, MetadataError>;
}
```

See [metadata.md](./modules/metadata.md) for `MetadataKey`, `MetadataPrivateKey`, `ResourceMetadata`, `MetadataKeyType`, `MetadataEncryptionKey`, `MetadataTypesSettings`, `MetadataKeysSettings`, `ProgressReporter`.

---

### CryptoService

```rust
impl CryptoService {
    /// Generate a new OpenPGP key pair
    /// Async: No (CPU-bound) | Errors: KeyGenerationFailed, UnsupportedAlgorithm
    pub fn generate_key(&self, params: KeyGenerationParams) -> Result<GeneratedKeyPair, CryptoError>;

    /// Encrypt a message with a recipient's public key
    /// Async: No | Errors: EncryptionFailed, InvalidKey
    pub fn encrypt(&self, plaintext: &str, recipient_key: &PublicKey, signing_key: Option<&DecryptedPrivateKey>) -> Result<String, CryptoError>;

    /// Encrypt a message symmetrically with password(s)
    /// Async: No | Errors: EncryptionFailed
    pub fn encrypt_symmetric(&self, plaintext: &str, passwords: &[&str], signing_key: Option<&DecryptedPrivateKey>) -> Result<String, CryptoError>;

    /// Decrypt an armored PGP message with a private key
    /// Async: No | Errors: DecryptionFailed, SignatureVerificationFailed
    pub fn decrypt(&self, armored_message: &str, private_key: &DecryptedPrivateKey, verification_keys: Option<&[PublicKey]>) -> Result<String, CryptoError>;

    /// Decrypt with a pre-extracted session key (bulk optimization)
    /// Async: No | Errors: DecryptionFailed, SignatureVerificationFailed
    pub fn decrypt_with_session_key(&self, armored_message: &str, session_key: &SessionKey, verification_keys: Option<&[PublicKey]>) -> Result<String, CryptoError>;

    /// Decrypt a symmetric message
    /// Async: No | Errors: DecryptionFailed
    pub fn decrypt_symmetric(&self, armored_message: &str, password: &str, verification_keys: Option<&[PublicKey]>) -> Result<String, CryptoError>;

    /// Extract session key from an encrypted message
    /// Async: No | Errors: DecryptionFailed
    pub fn get_session_key(&self, armored_message: &str, private_key: &DecryptedPrivateKey) -> Result<SessionKey, CryptoError>;

    /// Sign a message
    /// Async: No | Errors: InvalidKey
    pub fn sign(&self, message: &str, private_key: &DecryptedPrivateKey) -> Result<String, CryptoError>;

    /// Verify a signed message
    /// Async: No | Errors: SignatureVerificationFailed
    pub fn verify(&self, signed_message: &str, verification_keys: &[PublicKey]) -> Result<String, CryptoError>;

    /// Decrypt (unlock) a private key with passphrase
    /// Async: No | Errors: InvalidPassphrase, InvalidKey
    pub fn decrypt_private_key(&self, armored_key: &str, passphrase: &str) -> Result<DecryptedPrivateKey, CryptoError>;

    /// Re-encrypt a private key with a new passphrase
    /// Async: No | Errors: EncryptionFailed
    pub fn encrypt_private_key(&self, private_key: &DecryptedPrivateKey, new_passphrase: &str) -> Result<String, CryptoError>;

    /// Validate passphrase against a private key (convenience for decrypt_private_key)
    /// Async: No | Errors: InvalidPassphrase
    pub fn check_passphrase(&self, armored_key: &str, passphrase: &str) -> Result<(), CryptoError>;

    /// Extract metadata from an armored key
    /// Async: No | Errors: InvalidKey
    pub fn get_key_info(&self, armored_key: &str) -> Result<GpgKeyInfo, CryptoError>;

    /// Access the keyring
    pub fn keyring(&self) -> &Keyring;
}
```

See [crypto.md](./modules/crypto.md) for `KeyGenerationParams`, `KeyType`, `GeneratedKeyPair`, `GpgKeyInfo`, `KeyUserId`, `SessionKey`, `DecryptedPrivateKey`.

---

### TagsClient

```rust
impl<T: Transport, S: Storage> TagsClient<T, S> {
    /// Find all tags accessible to the current user
    /// Async: Yes | Errors: Transport
    pub async fn find_all(&self) -> Result<Vec<Tag>, TagError>;

    /// Add a tag to a resource (creates tag if it doesn't exist)
    /// Async: Yes | Errors: DuplicateSlug, ValidationFailed, InsufficientPermissions, Transport
    pub async fn add_to_resource(&self, resource_id: &Uuid, slug: &str) -> Result<Tag, TagError>;

    /// Replace all tags on a resource
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn update_resource_tags(&self, resource_id: &Uuid, tags: &[String]) -> Result<Vec<Tag>, TagError>;

    /// Rename a tag
    /// Async: Yes | Errors: NotFound, DuplicateSlug, ValidationFailed, InsufficientPermissions, Transport
    pub async fn update(&self, id: &Uuid, slug: &str) -> Result<Tag, TagError>;

    /// Delete a tag and all its associations
    /// Async: Yes | Errors: NotFound, InsufficientPermissions, Transport
    pub async fn delete(&self, id: &Uuid) -> Result<(), TagError>;
}
```

See [tags-comments.md](./modules/tags-comments.md) for `Tag`.

---

### CommentsClient

```rust
impl<T: Transport, S: Storage> CommentsClient<T, S> {
    /// Find all comments for a resource (sorted by creation date)
    /// Async: Yes | Errors: Transport
    pub async fn find_all_by_resource(&self, resource_id: &Uuid) -> Result<Vec<Comment>, CommentError>;

    /// Create a comment on a resource (with optional threading)
    /// Async: Yes | Errors: ValidationFailed, InsufficientPermissions, Transport
    pub async fn create(&self, resource_id: &Uuid, content: &str, parent_id: Option<Uuid>) -> Result<Comment, CommentError>;

    /// Delete a comment (creator or admin only)
    /// Async: Yes | Errors: NotFound, InsufficientPermissions, Transport
    pub async fn delete(&self, id: &Uuid) -> Result<(), CommentError>;
}
```

See [tags-comments.md](./modules/tags-comments.md) for `Comment`.

---

### RolesClient

```rust
impl<T: Transport, S: Storage> RolesClient<T, S> {
    /// Get all roles
    /// Async: Yes | Errors: Transport
    pub async fn get_all(&self) -> Result<Vec<Role>, UserError>;

    /// Sync local role cache with server
    /// Async: Yes | Errors: Transport, Storage
    pub async fn update_local_storage(&self) -> Result<(), UserError>;
}
```

### RbacClient

```rust
impl<T: Transport, S: Storage> RbacClient<T, S> {
    /// Get current user's RBAC permissions
    /// Async: Yes | Errors: Transport
    pub async fn find_me(&self) -> Result<RbacPermissions, UserError>;
}
```

---

### ConfigClient

```rust
impl<T: Transport, S: Storage> ConfigClient<T, S> {
    /// Get a configuration value by key
    /// Async: Yes | Errors: Storage
    pub async fn get(&self, key: &str) -> Result<Option<String>, ConfigError>;

    /// Get all configuration values
    /// Async: Yes | Errors: Storage
    pub async fn get_all(&self) -> Result<HashMap<String, String>, ConfigError>;

    /// Get the configured server URL
    /// Async: No | Errors: None
    pub fn server_url(&self) -> &str;

    /// Get the SDK version
    /// Async: No | Errors: None
    pub fn version(&self) -> &str;

    /// Check if the SDK is configured (server URL + account set)
    /// Async: Yes | Errors: Storage
    pub async fn is_configured(&self) -> Result<bool, ConfigError>;

    /// Validate a server domain URL
    /// Async: Yes | Errors: InvalidDomain, Transport
    pub async fn check_domain(&self, url: &str) -> Result<(), ConfigError>;

    /// Get the user's account info
    /// Async: Yes | Errors: Storage
    pub async fn get_account(&self) -> Result<AccountInfo, ConfigError>;

    /// Get organization settings
    /// Async: Yes | Errors: Transport
    pub async fn get_organization_settings(&self) -> Result<OrganizationSettings, ConfigError>;

    /// Get password policies
    /// Async: Yes | Errors: Transport
    pub async fn get_password_policies(&self) -> Result<PasswordPolicies, ConfigError>;

    /// Get password policies (admin view)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn get_password_policies_admin(&self) -> Result<PasswordPolicies, ConfigError>;

    /// Save password policies (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn save_password_policies(&self, settings: PasswordPolicies) -> Result<(), ConfigError>;

    /// Get passphrase policies
    /// Async: Yes | Errors: Transport
    pub async fn get_passphrase_policies(&self) -> Result<PassphrasePolicies, ConfigError>;

    /// Save passphrase policies (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn save_passphrase_policies(&self, settings: PassphrasePolicies) -> Result<(), ConfigError>;

    /// Get locale
    /// Async: Yes | Errors: Storage
    pub async fn get_locale(&self) -> Result<String, ConfigError>;

    /// Update locale
    /// Async: Yes | Errors: Transport, Storage
    pub async fn update_locale(&self, locale: &str) -> Result<(), ConfigError>;

    /// Find available themes
    /// Async: Yes | Errors: Transport
    pub async fn find_themes(&self) -> Result<Vec<Theme>, ConfigError>;

    /// Change active theme
    /// Async: Yes | Errors: Transport
    pub async fn change_theme(&self, name: &str) -> Result<(), ConfigError>;

    /// Get export policies
    /// Async: Yes | Errors: Transport
    pub async fn get_export_policies(&self) -> Result<ExportPolicies, ConfigError>;

    /// Get remember-me user choice
    /// Async: Yes | Errors: Storage
    pub async fn get_remember_me_choice(&self) -> Result<Option<bool>, ConfigError>;

    /// Get subscription info (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn get_subscription(&self) -> Result<Subscription, ConfigError>;

    /// Update subscription key (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn update_subscription(&self, key: &str) -> Result<Subscription, ConfigError>;
}

pub struct AccountInfo {
    pub user_id: Uuid,
    pub username: String,
    pub domain: String,
    pub first_name: String,
    pub last_name: String,
    pub server_public_key_fingerprint: String,
    pub user_public_key_fingerprint: String,
    pub user_private_armored_key: String,
}

pub struct OrganizationSettings {
    pub app: AppSettings,
    pub passbolt: PassboltSettings,
}

pub struct PasswordPolicies {
    pub default_generator: String,  // "password" or "passphrase"
    pub password_length: u32,
    pub mask_upper: bool,
    pub mask_lower: bool,
    pub mask_digit: bool,
    pub mask_parenthesis: bool,
    pub mask_emoji: bool,
    pub mask_char1: bool,
    pub mask_char2: bool,
    pub mask_char3: bool,
    pub mask_char4: bool,
    pub mask_char5: bool,
    pub exclude_look_alike_chars: bool,
    pub passphrase_words: u32,
    pub passphrase_word_separator: String,
    pub passphrase_word_case: String,
}

pub struct PassphrasePolicies {
    pub entropy_minimum: u32,
    pub external_dictionary_check: bool,
}

pub struct Theme {
    pub id: Uuid,
    pub name: String,
    pub preview: String,
}

pub struct ExportPolicies {
    pub export_resources: String,  // "allow" or "deny"
}

pub struct Subscription {
    pub customer_id: String,
    pub subscription_id: String,
    pub users: u32,
    pub email: String,
    pub expiry: DateTime<Utc>,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```

---

### ResourceTypesClient

```rust
impl<T: Transport, S: Storage> ResourceTypesClient<T, S> {
    /// Get or find all resource types (cache-first)
    /// Async: Yes | Errors: Transport, Storage
    pub async fn get_or_find_all(&self) -> Result<Vec<ResourceType>, ResourceError>;

    /// Find all resource types (including deleted)
    /// Async: Yes | Errors: Transport
    pub async fn find_all(&self) -> Result<Vec<ResourceType>, ResourceError>;

    /// Update deleted status for resource types (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn update_deleted_status(&self, changes: &[ResourceTypeStatusChange]) -> Result<(), ResourceError>;
}

pub struct ResourceType {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub definition: serde_json::Value,
    pub deleted: bool,
}

pub struct ResourceTypeStatusChange {
    pub id: Uuid,
    pub deleted: bool,
}
```

---

### PasswordExpiryClient

```rust
impl<T: Transport, S: Storage> PasswordExpiryClient<T, S> {
    /// Get password expiry settings (cache-first)
    /// Async: Yes | Errors: Transport, Storage
    pub async fn get_settings(&self) -> Result<PasswordExpirySettings, SecretError>;

    /// Save password expiry settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn save_settings(&self, settings: PasswordExpirySettings) -> Result<(), SecretError>;

    /// Delete password expiry settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn delete_settings(&self) -> Result<(), SecretError>;
}
```

### SecretRevisionsClient

```rust
impl<T: Transport, S: Storage> SecretRevisionsClient<T, S> {
    /// Find all revisions for a resource
    /// Async: Yes | Errors: Transport
    pub async fn find_all_by_resource_id(&self, resource_id: &Uuid) -> Result<Vec<SecretRevision>, SecretError>;

    /// Get revision settings
    /// Async: Yes | Errors: Transport
    pub async fn find_settings(&self) -> Result<SecretRevisionSettings, SecretError>;

    /// Save revision settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn save_settings(&self, settings: SecretRevisionSettings) -> Result<(), SecretError>;

    /// Delete revision settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn delete_settings(&self) -> Result<(), SecretError>;
}

pub struct SecretRevisionSettings {
    pub retention_period: Option<u32>,  // days, None = keep forever
    pub max_revisions: Option<u32>,     // None = unlimited
}
```

---

### ActionLogsClient

```rust
impl<T: Transport, S: Storage> ActionLogsClient<T, S> {
    /// Find all action logs for an entity
    /// Async: Yes | Errors: Transport
    pub async fn find_all_for(&self, entity_id: &Uuid) -> Result<Vec<ActionLog>, ActionLogError>;
}

pub struct ActionLog {
    pub id: Uuid,
    pub action_id: String,
    pub type_: String,
    pub status: String,
    pub created: DateTime<Utc>,
    pub creator: Option<UserProfile>,
}

#[derive(Error, Debug)]
pub enum ActionLogError {
    #[error(transparent)]
    Transport(#[from] TransportError),
}
```

---

### AccountRecoveryClient

```rust
impl<T: Transport, S: Storage> AccountRecoveryClient<T, S> {
    /// Get organization recovery policy
    /// Async: Yes | Errors: Transport
    pub async fn get_policy(&self) -> Result<AccountRecoveryPolicy, AccountRecoveryError>;

    /// Save user's account recovery settings
    /// Async: Yes | Errors: Transport
    pub async fn save_user_settings(&self, settings: AccountRecoveryUserSettings) -> Result<(), AccountRecoveryError>;

    /// Get user's recovery requests
    /// Async: Yes | Errors: Transport
    pub async fn get_user_requests(&self) -> Result<Vec<AccountRecoveryRequest>, AccountRecoveryError>;

    /// Get a specific recovery request
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn get_request(&self, id: &Uuid) -> Result<AccountRecoveryRequest, AccountRecoveryError>;

    /// Recover an account
    /// Async: Yes | Errors: Crypto, Transport
    pub async fn recover(&self, params: RecoverAccountParams) -> Result<(), AccountRecoveryError>;

    /// Get recovery account info
    /// Async: Yes | Errors: Storage
    pub async fn get_account(&self) -> Result<AccountInfo, AccountRecoveryError>;

    /// Continue recovery process
    /// Async: Yes | Errors: Transport
    pub async fn continue_recovery(&self) -> Result<(), AccountRecoveryError>;

    /// Generate organization recovery key (admin)
    /// Async: No (CPU-bound) | Errors: Crypto
    pub fn generate_org_key(&self, params: KeyGenerationParams) -> Result<GeneratedKeyPair, AccountRecoveryError>;

    /// Download generated org key
    /// Async: No | Errors: Storage
    pub fn download_org_key(&self) -> Result<String, AccountRecoveryError>;

    /// Download recovery kit
    /// Async: No | Errors: Storage
    pub fn download_recovery_kit(&self) -> Result<Vec<u8>, AccountRecoveryError>;

    /// Check if user has postponed invitation
    /// Async: No | Errors: Storage
    pub fn has_postponed_invitation(&self) -> Result<bool, AccountRecoveryError>;

    /// Postpone invitation
    /// Async: Yes | Errors: Storage
    pub async fn postpone_invitation(&self) -> Result<(), AccountRecoveryError>;

    /// Check if user has enabled account recovery
    /// Async: Yes | Errors: Transport
    pub async fn has_user_enabled(&self) -> Result<bool, AccountRecoveryError>;

    /// Initiate an account recovery request
    /// Async: Yes | Errors: Transport
    pub async fn initiate_request(&self) -> Result<(), AccountRecoveryError>;

    /// Generate a key for account recovery request
    /// Async: No (CPU-bound) | Errors: Crypto
    pub fn generate_request_key(&self, params: KeyGenerationParams) -> Result<GeneratedKeyPair, AccountRecoveryError>;
}

pub struct AccountRecoveryPolicy {
    pub policy: String,  // "disabled", "opt-in", "opt-out", "mandatory"
    pub public_key: Option<String>,
}

pub struct AccountRecoveryUserSettings {
    pub status: String,  // "approved", "rejected"
}

pub struct AccountRecoveryRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: String,
    pub created: DateTime<Utc>,
}

pub struct RecoverAccountParams {
    pub passphrase: String,
    pub private_key: String,
}

#[derive(Error, Debug)]
pub enum AccountRecoveryError {
    #[error("Request not found: {id}")]
    NotFound { id: Uuid },
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```

---

### SetupClient

```rust
/// Handles initial account setup (onboarding a new user).
/// The setup flow guides the user through key generation/import, security token configuration,
/// and account completion. It uses data from the setup URL token provided by the server.
pub struct SetupClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    crypto: Arc<CryptoService>,
}

impl<T: Transport, S: Storage> SetupClient<T, S> {
    /// Start the setup process - fetches setup info from the server using the URL token
    /// Async: Yes | Errors: Transport, InvalidSetupToken
    pub async fn start(&self, user_id: &Uuid, token: &Uuid) -> Result<SetupInfo, SetupError>;

    /// Import an existing private key for the account
    /// Async: No | Errors: InvalidKey, Crypto
    pub fn import_key(&self, armored_key: &str) -> Result<GpgKeyInfo, SetupError>;

    /// Set the security token (color + text code displayed to verify the extension is genuine)
    /// Async: No | Errors: InvalidSecurityToken
    pub fn set_security_token(&self, token: SecurityToken) -> Result<(), SetupError>;

    /// Complete the setup - registers the public key with the server and finalizes the account
    /// Async: Yes | Errors: Transport, Crypto, SetupIncomplete
    pub async fn complete(&self, passphrase: &str) -> Result<(), SetupError>;

    /// Download the recovery kit (armored private key for backup)
    /// Async: No | Errors: SetupIncomplete
    pub fn download_recovery_kit(&self) -> Result<Vec<u8>, SetupError>;

    /// Check if this is the first extension install (no existing account configured)
    /// Async: Yes | Errors: Storage
    pub async fn is_first_install(&self) -> Result<bool, SetupError>;
}

pub struct SetupInfo {
    pub user_id: Uuid,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub domain: String,
    pub server_public_key: String,
}

pub struct SecurityToken {
    pub code: String,       // 3-character code
    pub color: String,      // hex color e.g. "#ff0000"
    pub textcolor: String,  // hex color for text
}

#[derive(Error, Debug)]
pub enum SetupError {
    #[error("Invalid setup token")]
    InvalidSetupToken,
    #[error("Setup incomplete: {0}")]
    SetupIncomplete(String),
    #[error("Invalid security token: {0}")]
    InvalidSecurityToken(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```

---

### RecoverClient

```rust
/// Handles account recovery (recovering access after losing passphrase or device).
/// Similar to SetupClient but operates on an existing account. The user re-imports their
/// private key (from recovery kit) and re-authenticates.
pub struct RecoverClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    crypto: Arc<CryptoService>,
}

impl<T: Transport, S: Storage> RecoverClient<T, S> {
    /// Start the recovery process - fetches recovery info from the server
    /// Async: Yes | Errors: Transport, InvalidRecoveryToken
    pub async fn start(&self, user_id: &Uuid, token: &Uuid) -> Result<RecoverInfo, RecoverError>;

    /// Import the user's private key (from recovery kit backup)
    /// Async: No | Errors: InvalidKey, Crypto
    pub fn import_key(&self, armored_key: &str) -> Result<GpgKeyInfo, RecoverError>;

    /// Set the security token
    /// Async: No | Errors: InvalidSecurityToken
    pub fn set_security_token(&self, token: SecurityToken) -> Result<(), RecoverError>;

    /// Complete the recovery - re-registers with the server
    /// Async: Yes | Errors: Transport, Crypto, RecoveryIncomplete
    pub async fn complete(&self, passphrase: &str) -> Result<(), RecoverError>;

    /// Check if this is the first install
    /// Async: Yes | Errors: Storage
    pub async fn is_first_install(&self) -> Result<bool, RecoverError>;

    /// Handle lost passphrase case - redirect to account recovery request flow
    /// Async: No
    pub fn lost_passphrase_case(&self) -> Result<LostPassphraseAction, RecoverError>;
}

pub struct RecoverInfo {
    pub user_id: Uuid,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub domain: String,
    pub server_public_key: String,
}

pub enum LostPassphraseAction {
    /// Account recovery is available - user can request a recovery
    AccountRecoveryAvailable,
    /// No recovery option - user must contact admin
    ContactAdmin,
}

#[derive(Error, Debug)]
pub enum RecoverError {
    #[error("Invalid recovery token")]
    InvalidRecoveryToken,
    #[error("Recovery incomplete: {0}")]
    RecoveryIncomplete(String),
    #[error("Invalid security token: {0}")]
    InvalidSecurityToken(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```

---

### ImportExportClient

```rust
impl<T: Transport, S: Storage> ImportExportClient<T, S> {
    /// Import resources from a file
    /// Async: Yes | Errors: ParseFailed, Crypto, Transport
    pub async fn import_file(&self, data: &[u8], format: ImportFormat) -> Result<ImportResult, ImportExportError>;

    /// Export resources to a file format
    /// Async: Yes | Errors: Crypto, Transport
    pub async fn export_to_file(&self, resource_ids: &[Uuid], format: ExportFormat) -> Result<Vec<u8>, ImportExportError>;
}

pub enum ImportFormat { Csv, Kdbx, Json, Pif }
pub enum ExportFormat { Csv, Kdbx, Json }

pub struct ImportResult {
    pub created: u32,
    pub errors: Vec<ImportError>,
}

pub struct ImportError {
    pub row: u32,
    pub message: String,
}

#[derive(Error, Debug)]
pub enum ImportExportError {
    #[error("Parse failed: {0}")]
    ParseFailed(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Transport(#[from] TransportError),
}
```

---

### ScimClient

```rust
impl<T: Transport, S: Storage> ScimClient<T, S> {
    /// Find SCIM settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn find_settings(&self) -> Result<ScimSettings, ConfigError>;

    /// Create SCIM settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn create_settings(&self, settings: ScimSettings) -> Result<ScimSettings, ConfigError>;

    /// Update SCIM settings (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn update_settings(&self, settings: ScimSettings) -> Result<ScimSettings, ConfigError>;

    /// Disable SCIM (admin)
    /// Async: Yes | Errors: InsufficientPermissions, Transport
    pub async fn disable(&self) -> Result<(), ConfigError>;
}

pub struct ScimSettings {
    pub enabled: bool,
    pub endpoint: String,
    pub token: Option<String>,
}
```

---

### MobileTransferClient

```rust
impl<T: Transport, S: Storage> MobileTransferClient<T, S> {
    /// Create a mobile transfer request
    /// Async: Yes | Errors: Transport
    pub async fn create_transfer(&self) -> Result<MobileTransfer, ConfigError>;

    /// Get a mobile transfer by ID
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn get_transfer(&self, id: &Uuid) -> Result<MobileTransfer, ConfigError>;

    /// Update a mobile transfer
    /// Async: Yes | Errors: NotFound, Transport
    pub async fn update_transfer(&self, id: &Uuid, data: &MobileTransferData) -> Result<MobileTransfer, ConfigError>;

    /// Export account for desktop app
    /// Async: Yes | Errors: Storage
    pub async fn export_account(&self) -> Result<AccountExport, ConfigError>;
}

pub struct MobileTransfer {
    pub id: Uuid,
    pub status: String,
    pub hash: Option<String>,
    pub current_page: u32,
    pub total_pages: u32,
}

pub struct MobileTransferData {
    pub current_page: u32,
    pub data: String,
}

pub struct AccountExport {
    pub user_id: Uuid,
    pub domain: String,
    pub user_private_armored_key: String,
    pub user_public_armored_key: String,
    pub server_public_armored_key: String,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
}
```

---

## End-to-End Workflow Examples

### Example 1: Login and fetch a decrypted password

```rust
// 1. Build SDK
let sdk = PassboltSdk::builder()
    .server_url("https://passbolt.example.com")
    .transport(reqwest_transport)
    .storage(sqlite_storage)
    .build()?;

// 2. Login
let session = sdk.auth().login(LoginParams {
    user_fingerprint: "ABCD1234...".into(),
    user_private_armored_key: armored_key.clone(),
    passphrase: "my-passphrase".into(),
    remember_me: true,
}).await?;

// 3. Find resources
let resources = sdk.resources().find(FindResourcesOptions {
    filters: ResourceFilters { is_owned_by_me: Some(true), ..Default::default() },
    contain: ResourceContain { favorite: true, ..Default::default() },
    orders: vec![ResourceOrder::ModifiedDesc],
    pagination: None, // fetch all
}).await?;

// 4. Decrypt a secret
let secret = sdk.secrets().find_and_decrypt(
    &resources[0].id,
    "my-passphrase",
).await?;

match secret {
    SecretData::PasswordAndDescription { password, description } => {
        println!("Password: {}", password);
    }
    _ => {}
}

// 5. Logout
sdk.auth().logout().await?;
```

### Example 2: Create and share a resource

```rust
// Create a resource
let resource = sdk.resources().create(CreateResourceParams {
    name: "Production DB".into(),
    username: Some("admin".into()),
    uri: Some("postgres://prod.example.com".into()),
    description: None,
    resource_type_id: password_and_description_type_id,
    folder_parent_id: Some(engineering_folder_id),
    secret: SecretData::PasswordAndDescription {
        password: "super-secret-123".into(),
        description: "Read-only production credentials".into(),
    },
    passphrase: "my-passphrase".into(),
}).await?;

// Share with a colleague
let aros = sdk.sharing().search_aros("alice").await?;
let alice_id = match &aros[0] {
    Aro::User(u) => u.id,
    _ => panic!("Expected user"),
};

sdk.sharing().share_resources(
    &[resource.id],
    PermissionChanges {
        created: vec![PermissionChange {
            id: None,
            aro: AroType::User,
            aro_foreign_key: alice_id,
            permission_type: Some(PermissionType::Read),
        }],
        updated: vec![],
        deleted: vec![],
    },
    "my-passphrase",
).await?;
```

### Example 3: Group member management with re-encryption

```rust
// Add a new member to a group (triggers re-encryption of all shared secrets)
sdk.groups().update(
    &group_id,
    UpdateGroupParams {
        name: None,
        members_added: vec![GroupMemberParam { user_id: new_user_id, is_admin: false }],
        members_updated: vec![],
        members_removed: vec![],
    },
    "my-passphrase",
).await?;
```
