# bolty

`bolty` is a command-line tool for injecting Passbolt secrets into local
configuration files.

Write Passbolt references in a template such as `.env.tpl`, let `bolty`
resolve and decrypt those references through the Passbolt API, and write a
local config file containing the resolved values.

## Install

With Homebrew:

```bash
brew tap emqMalte/homebrew-tap
brew install --cask bolty
```

Verify the binary:

```bash
bolty --version
bolty --help
```

## Configure Passbolt

The recommended setup path is a Passbolt account kit:

```bash
bolty configure --account-kit ~/Downloads/account-kit.passbolt
```

To download an account kit, open Passbolt in the browser, open the profile
menu, go to **Manage account**, open **Desktop app setup**, and download the
account kit.

You can also configure a profile manually:

```bash
bolty configure \
  --server-url https://passbolt.example \
  --user-id 8bb80df5-700c-48ce-b568-85a60fc3c8f2 \
  --private-key ~/.keys/passbolt-private.asc
```

`configure` validates the Passbolt server public-key fingerprint before saving
anything. For unattended setup, pass the expected fingerprint:

```bash
bolty configure \
  --account-kit ~/Downloads/account-kit.passbolt \
  --accept-server-fingerprint 0123456789ABCDEF0123456789ABCDEF01234567
```

For CI or other non-interactive environments, pass the private-key passphrase by
environment variable name:

```bash
export PASSBOLT_PRIVATE_KEY_PASSPHRASE='...'
bolty configure \
  --account-kit account-kit.passbolt \
  --passphrase-env PASSBOLT_PRIVATE_KEY_PASSPHRASE \
  --accept-server-fingerprint 0123456789ABCDEF0123456789ABCDEF01234567
```

If your Passbolt account requires TOTP during setup or login, pass `--totp`:

```bash
bolty configure --account-kit account-kit.passbolt --totp 123456
bolty login --totp 123456
```

Profiles are optional. When `--profile` is omitted, `default` is used. To
configure a named profile:

```bash
bolty configure staging --account-kit staging.passbolt --set-default
```

Advanced profile management commands:

```bash
bolty profile list
bolty profile set-default staging
bolty profile remove staging
```

## Login and Status

Authenticate and store a Passbolt session:

```bash
bolty login
```

Commands that unlock the private key resolve the passphrase in this order:

1. `--passphrase-env <environment-variable-name>`
2. Stored OS keychain entry for the profile
3. Interactive prompt where supported

Check the stored session:

```bash
bolty status
```

Logout invalidates the stored server session and removes session-like secrets
from the OS keychain:

```bash
bolty logout
```

The profile metadata and private key remain configured so you can log in again.

## Inject Secrets

`bolty inject` replaces Passbolt references in a text template with decrypted
resource fields:

```bash
bolty inject --input .env.tpl --output .env
```

Template references use this form:

```text
{{ passbolt://<resource-uuid-or-exact-name>/<field> }}
```

Selectors can be a resource UUID or an exact resource name:

```dotenv
DATABASE_PASSWORD={{ passbolt://8bb80df5-700c-48ce-b568-85a60fc3c8f2/password }}
POSTGRES_PASSWORD={{ passbolt://postgres-prod/password }}
```

Supported fields:

- `name`
- `username`
- `password`
- `uri`
- `url`
- `description`
- `totp`
- `custom/<id-or-name>`

Template injection works inside larger strings:

```dotenv
POSTGRES_URL=postgres://{{ passbolt://postgres-prod/username }}:{{ passbolt://postgres-prod/password }}@{{ passbolt://postgres-prod/uri }}/app
```

Output files are created with `0600` permissions by default:

```bash
bolty inject --input .env.tpl --output .env --file-mode 0640
```

Write to stdout instead of a file by omitting `--output`:

```bash
bolty inject --input .env.tpl
```

## Resources

List safe resource summaries as JSON:

```bash
bolty resources list
```

Search visible summary fields:

```bash
bolty resources list --search postgres
```

Fetch and decrypt a single resource by UUID or exact name:

```bash
bolty resources get 8bb80df5-700c-48ce-b568-85a60fc3c8f2
bolty resources get postgres-prod
```

## TLS Verification

`configure`, `login`, `status`, `logout`, `inject`, and `resources` accept:

```bash
--insecure-skip-tls-verify
```

This disables TLS certificate validation for that single invocation. The flag is
intended only for local development against self-signed Passbolt instances on a
trusted network.

- The flag is never persisted to the profile.
- A `WARNING:` is printed to stderr when the flag is active.
- Do not use it against any Passbolt server reached over an untrusted network.

## License

This project is licensed under AGPL-3.0-only. See [LICENSE](LICENSE).

Parts of `generated/passbolt/` are generated from the Passbolt OpenAPI schema
(AGPL-3.0, Passbolt SA). See [NOTICE.md](NOTICE.md).
