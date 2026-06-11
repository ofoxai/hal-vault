# Security

## Threat model

### What hal-vault protects

- **Secrets at rest.** The entire database (`secrets.db`, and its previous
  generation `secrets.db.bak`) is a single blob encrypted with
  [age](https://github.com/FiloSottile/age) to your SSH public key
  (`ssh-ed25519` or `ssh-rsa`, via `filippo.io/age/agessh`). An attacker who
  obtains the vault files — from a backup, a synced folder, a stolen disk, or
  a leaked object store — but does not hold your SSH private key learns
  nothing about your secrets beyond the file size. This is age's guarantee;
  hal-vault adds no cryptography of its own.
- **Accidental disclosure in tooling.** Raw secret values reach stdout only
  through the explicit `get --reveal` flag. Tables, detail views, JSON
  without `--reveal`, error messages, and prompts only ever show a mask that
  reveals at most 8 characters. Secret values are never accepted on the
  command line, so they do not appear in shell history or process listings.
- **Local file hygiene.** The vault directory is created with mode `0700` and
  its files with mode `0600`. Saves are atomic and durable: the new database
  is written and fsynced to a temporary file, the previous generation is kept
  as `secrets.db.bak` (a hard-linked snapshot), and a single rename replaces
  `secrets.db` — a complete database exists at every instant, even across
  crashes. Concurrent hal-vault processes serialize writes through an
  exclusive advisory lock (`.lock` in the vault directory), so simultaneous
  commands cannot lose each other's writes.

### What hal-vault does NOT protect

- **A compromised host with a usable private key.** If an attacker can run
  code as you and your SSH private key is unencrypted, agent-loaded, or its
  passphrase can be captured, they can decrypt the vault. hal-vault is not a
  defense against malware on the machine that legitimately decrypts the
  vault.
- **Memory inspection.** Decrypted secrets exist in process memory while
  hal-vault (or a program using the library) runs. hal-vault does not attempt
  memory locking, zeroization guarantees, or protection from debuggers and
  core dumps.
- **Voluntary disclosure after `--reveal`.** `--reveal` is the deliberate
  boundary where a secret leaves the vault's control. Anything that happens
  after that — an agent echoing the value, a script writing it to a log, an
  environment variable inherited by a child process — is outside hal-vault's
  threat model.

## Reporting a vulnerability

Please report security issues privately via a
[GitHub security advisory](https://github.com/ofoxai/hal-vault/security/advisories/new).
Do not open public issues for vulnerabilities. We will respond as quickly as
we can and coordinate a fix and disclosure timeline with you.
