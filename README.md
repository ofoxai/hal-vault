# hal-vault

hal-vault is a simple, modern and secure secret store CLI and Go library, with SSH-key encryption, tag search, and agent-safe masked output — built on [age](https://github.com/FiloSottile/age), built for AI agents.

- **One encrypted file.** Your whole vault is a single age-encrypted blob (`secrets.db`) plus an automatic previous-generation backup (`secrets.db.bak`). Saves are atomic and durable, writes are serialized across processes with an advisory lock. Easy to copy, sync, and audit.
- **SSH keys are the keys.** A dedicated `~/.ssh/hal-vault_ed25519` key pair is generated on first init, or bring your own existing `ssh-ed25519` / `ssh-rsa` pair with `-r`/`-i` (passphrase-protected keys are prompted on the terminal). The same key discipline you already trust for SSH.
- **Masked by default.** Every table, detail view, and JSON output shows secrets masked (`sk-p…7890 (24 chars)`). Raw values reach stdout only through the explicit `--reveal` flag.
- **Never on argv.** Secret values are read from stdin or a hidden terminal prompt — they never appear in shell history or `ps` output.
- **Tag search.** Free-text query plus exact `--tag` and `--type` filters.
- **A real Go library.** The `vault` package is part of the product, not an `internal/` afterthought.
- **Minimal dependencies.** `filippo.io/age`, `golang.org/x/crypto`, `golang.org/x/term`, `golang.org/x/sys`, and the standard library. No frameworks.

## Installation

### Pre-built binaries

Binaries for Linux, macOS, and Windows are published on the
[releases page](https://github.com/ofoxai/hal-vault/releases), packaged as
`hal-vault-<version>-<os>-<arch>.tar.gz` (`.zip` for Windows) with build
provenance attestations.

```
# Download the archive for your platform, e.g. with the GitHub CLI:
gh release download v0.0.1 --repo ofoxai/hal-vault --pattern '*darwin-arm64*'

# Unpack and install:
tar -xzf hal-vault-v0.0.1-darwin-arm64.tar.gz
install -m 0755 hal-vault/hal-vault /usr/local/bin/hal-vault
hal-vault version
```

Provenance can be verified with `gh attestation verify <archive> --repo ofoxai/hal-vault`.

### From source

```
go install github.com/ofoxai/hal-vault/cmd/hal-vault@latest
```

## Usage

### Initialize a vault

`init` binds the vault to an SSH key pair. By default it uses the dedicated
key `~/.ssh/hal-vault_ed25519(.pub)`, generating it on first use — your
day-to-day SSH keys stay untouched, and rotating them never locks the vault.

```
$ hal-vault init
generated SSH key pair: /home/you/.ssh/hal-vault_ed25519
initialized vault in /home/you/.hal-vault
recipient: /home/you/.ssh/hal-vault_ed25519.pub
identity:  /home/you/.ssh/hal-vault_ed25519
```

To use an existing SSH key instead, pass `-r` / `-i` (any `ssh-ed25519` or
`ssh-rsa` pair works), and pick the database directory with `-d`:

```
$ hal-vault init -r ~/.ssh/id_rsa.pub -i ~/.ssh/id_rsa -d /srv/team-vault
initialized vault in /srv/team-vault
recipient: /home/you/.ssh/id_rsa.pub
identity:  /home/you/.ssh/id_rsa
```

Every command accepts `-d` to select the vault directory; the
`HAL_VAULT_DIR` environment variable works too.

### Add a secret

The value is never passed as an argument. Pipe it on stdin — from a file,
the clipboard, or another tool — or run interactively for a hidden double
prompt. (Avoid `echo "secret" | …`: hal-vault never sees argv, but your
shell history would still record the literal.)

```
$ hal-vault add openai -t api_key --tags llm,prod -n "OpenAI production key" < openai.key
added 7q3k2m openai: sk-p…7890 (24 chars)

$ pbpaste | hal-vault add anthropic -t api_key --tags llm
added 2w8c4d anthropic: sk-a…x2Qz (32 chars)
```

```
$ hal-vault add github-pat -t token --tags ci
Enter secret value:
Confirm secret value:
added 9x4n8p github-pat: gh…cd (12 chars)
```

### Get a secret (masked by default)

```
$ hal-vault get openai
id:      7q3k2m
label:   openai
type:    api_key
tags:    llm, prod
note:    OpenAI production key
value:   sk-p…7890 (24 chars)
created: 2026-06-11 10:32
updated: 2026-06-11 10:32
```

### Reveal a secret (the single explicit boundary)

`--reveal` prints the raw value and a single trailing newline, nothing else —
designed for shell substitution:

```
$ export OPENAI_API_KEY=$(hal-vault get openai --reveal)
```

With `--json`, the `value` field is included only when `--reveal` is also
given:

```
$ hal-vault get openai --json
{
  "id": "7q3k2m",
  "label": "openai",
  "type": "api_key",
  "tags": [
    "llm",
    "prod"
  ],
  "note": "OpenAI production key",
  "masked": "sk-p…7890 (24 chars)",
  "created_at": "2026-06-11T10:32:05.123456Z",
  "updated_at": "2026-06-11T10:32:05.123456Z"
}
```

### List everything

Always masked.

```
$ hal-vault list
ID      TYPE     LABEL       TAGS      MASKED                UPDATED
7q3k2m  api_key  openai      llm,prod  sk-p…7890 (24 chars)  2026-06-11 10:32
9x4n8p  token    github-pat  ci        gh…cd (12 chars)      2026-06-11 10:33
```

### Search

Case-insensitive substring over label, note, tags, and type, AND-combined
with exact `--tag` and `--type` filters:

```
$ hal-vault search prod --type api_key
ID      TYPE     LABEL   TAGS      MASKED                UPDATED
7q3k2m  api_key  openai  llm,prod  sk-p…7890 (24 chars)  2026-06-11 10:32
```

### Update

Metadata flags update in place; `--tags` replaces the whole tag list. The
boolean `--value` flag reads a new secret from stdin or the hidden prompt,
exactly like `add`:

```
$ hal-vault update openai --tags llm,prod,team-a -n "rotated 2026-06"
updated 7q3k2m openai: sk-p…7890 (24 chars)

$ hal-vault update openai --value < rotated-openai.key
updated 7q3k2m openai: sk-p…4321 (24 chars)
```

### Remove

Asks for confirmation on a terminal (skip with `-f`; non-interactive use
requires `-f`):

```
$ hal-vault rm github-pat
remove 9x4n8p (github-pat)? [y/N] y
removed 9x4n8p github-pat: gh…cd (12 chars)
```

## Built for agents

hal-vault is designed to be handed to an AI agent without handing it your
secrets:

- **Masked by default.** `get`, `list`, and `search` never print raw values.
  The mask reveals at most 8 characters of any secret
  (`sk-p…7890 (24 chars)`), so an agent can identify and manage entries
  without ever seeing them.
- **`--reveal` is the single explicit boundary.** Raw values reach stdout
  only when `--reveal` is given: as the bare value plus a trailing newline
  (plain mode), or as the `value` field in `--json` output. Without
  `--reveal`, no output mode ever contains the raw value. That makes it
  trivially auditable and composable —
  `export KEY=$(hal-vault get openai --reveal)` moves a secret into a process
  environment without it ever appearing in agent transcripts, tables, or
  logs.
- **Secrets never on argv.** Values are read from stdin or a hidden terminal
  prompt, so they never leak via shell history, process listings, or
  command-logging hooks.
- **`--json` for machine parsing.** Every read command has a `--json` mode
  with stable fields; the `value` field appears only when `--reveal` is also
  given.
- **One encrypted file, the host's own trust anchor.** The entire vault is a
  single age-encrypted blob keyed to the machine's existing SSH key. There is
  no daemon, no network, no cloud account — the attack surface is one file
  and one key you already protect.

## Library

The `vault` package is a supported public API:

```go
package main

import (
	"fmt"
	"log"

	"github.com/ofoxai/hal-vault/vault"
)

func main() {
	store, err := vault.Open(vault.DefaultDir())
	if err != nil {
		log.Fatal(err)
	}

	db, err := store.Load()
	if err != nil {
		log.Fatal(err)
	}

	entry, err := db.Get("openai")
	if err != nil {
		log.Fatal(err)
	}

	// The library never prints, and errors never contain secret values.
	fmt.Println(entry.Masked()) // sk-p…7890 (24 chars)
}
```

The library never writes to stdout/stderr, and its errors never contain entry
values. `vault.Mask` implements the masking rules and is usable on its own.

## Threat model

hal-vault inherits age's at-rest guarantees: an attacker who obtains
`secrets.db` but not your SSH private key learns nothing about your secrets.
It does not protect against a compromised host with a usable private key, nor
against an agent that voluntarily leaks a value after `--reveal`. See
[SECURITY.md](SECURITY.md) for the full threat model and how to report
vulnerabilities.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
