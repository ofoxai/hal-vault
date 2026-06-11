# Changelog

## v0.1.0 (unreleased)

Initial release.

- Single-file vault: the whole database is one age-encrypted blob
  (`secrets.db`) with an automatic previous-generation backup
  (`secrets.db.bak`) and atomic, durable saves (fsync + single rename; a
  complete database exists at every instant).
- Concurrency-safe writes: mutating commands serialize through an exclusive
  advisory file lock, so concurrent hal-vault processes cannot lose each
  other's writes.
- SSH-key encryption via `filippo.io/age/agessh`: encrypt to `ssh-ed25519`
  or `ssh-rsa` public keys, decrypt with the matching OpenSSH private key,
  with terminal passphrase prompting for protected keys.
- Entry model with id, label, value, type (`api_key`, `password`, `token`,
  `ssh_key`, `cert`, `identity`, `other`), tags, note, and timestamps.
- Agent-safe masking: all output is masked by default, revealing at most
  8 characters of any secret; raw values reach stdout only via
  `get --reveal`.
- CLI commands: `init`, `add`, `get`, `list`, `search`, `update`, `rm`,
  `version`, `help` — with `--json` output for machine parsing and `-d` /
  `HAL_VAULT_DIR` vault-directory overrides.
- Secrets are never accepted on argv: values are read from stdin or a hidden
  double prompt on the terminal.
- Search with case-insensitive substring query plus exact `--tag` and
  `--type` filters.
- Public Go library (`github.com/ofoxai/hal-vault/vault`) that never prints
  and whose errors never contain secret values.
