# Changelog

## v0.0.3 - 2026-06-11

- Homebrew is now the recommended install: `brew install ofoxai/tap/hal-vault`.
- The CLI found its voice. Messages are calmer, clearer, and occasionally
  quote a certain shipboard computer.
- A much leaner README.

## v0.0.2 - 2026-06-11

- `init` now generates a dedicated `~/.ssh/hal-vault_ed25519` key instead of
  borrowing your day-to-day SSH keys. Use `-r`/`-i` for an existing key,
  `-d` for the vault directory.
- New library function: `vault.GenerateSSHKeyPair`.
- Companion agent skill: `npx skills add ofoxai/hal-vault-skill`.

## v0.0.1 - 2026-06-11

Initial release: a single age-encrypted vault file keyed to an SSH key.
CRUD and tag search, masked-by-default output (`--reveal` is the only way
out), values never on argv, atomic durable saves, cross-process locking,
and a public Go library.
