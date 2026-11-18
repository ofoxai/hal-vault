# Changelog

## v0.1.0 - 2026-11-18

- New `hal7://` references: an environment value of exactly
  `hal7://<label-or-id>` points at a vault entry and is resolved like `get`.
- New `hal-vault run [--env-file FILE]... [--no-masking] -- CMD`: resolves
  every reference in the environment and the env files with a single
  decryption, then runs CMD with the values in its environment only. Any
  unresolved reference stops it before CMD starts, listing all of them.
  Secrets (6+ characters) are masked in CMD's stdout and stderr, across
  write boundaries too; stdin, SIGINT/SIGTERM and the exit code pass
  through.
- New `hal-vault check [--env-file FILE]...`: verifies that every reference
  resolves and prints only masked values — for CI and pre-flight checks.
- Env files (by convention `.env.tpl`) are a dotenv subset: `export`,
  comments, blank lines, single and double quotes.

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
