# hal-vault

A simple, modern and secure secret store CLI and Go library — SSH-key
encryption, tag search, agent-safe masked output. Built on
[age](https://github.com/FiloSottile/age), built for AI agents.

- **One encrypted file.** The whole vault is a single age-encrypted blob
  with an automatic previous-generation backup. Saves are atomic and
  durable; concurrent writes serialize through a lock.
- **SSH keys are the keys.** A dedicated `~/.ssh/hal-vault_ed25519` is
  generated on first init — or bring your own ed25519/RSA key.
- **Masked by default.** Output shows `sk-p…7890 (24 chars)`, never the
  value. Raw secrets reach stdout only through `--reveal`.
- **Never on argv.** Values come from stdin or a hidden prompt — not from
  shell history, not from `ps`.
- **Minimal.** age, x/crypto, x/term, x/sys, and the standard library.
  No frameworks, no daemon, no cloud.

## Install

macOS / Linux (recommended):

```
brew install ofoxai/tap/hal-vault
```

Pre-built binaries for Linux, macOS, and Windows — with build provenance
attestations — are on the
[releases page](https://github.com/ofoxai/hal-vault/releases):

```
curl -LO https://github.com/ofoxai/hal-vault/releases/download/v0.0.3/hal-vault-v0.0.3-darwin-arm64.tar.gz
tar -xzf hal-vault-v0.0.3-darwin-arm64.tar.gz
sudo install -m 0755 hal-vault/hal-vault /usr/local/bin/hal-vault
```

(Binaries downloaded through a browser on macOS may need
`xattr -d com.apple.quarantine <file>` first.)

From source: `go install github.com/ofoxai/hal-vault/cmd/hal-vault@latest`

## Usage

```
$ hal-vault init
generated SSH key pair: /home/you/.ssh/hal-vault_ed25519
initialized vault in /home/you/.hal-vault
recipient: /home/you/.ssh/hal-vault_ed25519.pub
identity:  /home/you/.ssh/hal-vault_ed25519
hal-vault is fully operational.
```

`init -r`/`-i` binds an existing SSH key pair instead; `-d` picks the vault
directory (every command accepts `-d`; `HAL_VAULT_DIR` works too).

Add a secret — the value is read from stdin or a hidden double prompt,
never from the command line:

```
$ hal-vault add openai -t api_key --tags llm,prod < openai.key
added 7q3k2m openai: sk-p…7890 (24 chars)
```

Find and inspect — always masked:

```
$ hal-vault search llm
ID      TYPE     LABEL   TAGS      MASKED                UPDATED
7q3k2m  api_key  openai  llm,prod  sk-p…7890 (24 chars)  2026-06-11 10:32
```

Use a secret — `--reveal` prints the raw value plus one newline, made for
command substitution:

```
$ OPENAI_API_KEY="$(hal-vault get openai --reveal)" ./deploy.sh
```

Rotate and remove:

```
$ hal-vault update openai --value < rotated.key
$ hal-vault rm openai
```

`hal-vault help` covers the rest: entry types, `--json` output, exit codes.

## Built for agents

`--reveal` is the single explicit boundary: without it, no output mode —
table, detail view, JSON, or error — ever contains a raw value. An agent
can hold the vault without ever holding the secrets. The companion skill
teaches agents the discipline:

```
npx skills add ofoxai/hal-vault-skill
```

See [ofoxai/hal-vault-skill](https://github.com/ofoxai/hal-vault-skill).

## Library

```go
import "github.com/ofoxai/hal-vault/vault"

s, _ := vault.Open(vault.DefaultDir())
db, _ := s.Load()
for _, e := range db.Search("prod", "", "") {
    fmt.Println(e.ID, e.Label, e.Masked())
}
```

The `vault` package never prints, and its errors never contain secret
values.

## Security

An attacker who obtains the vault file but not your SSH private key learns
nothing beyond its size — that guarantee is age's. What hal-vault does and
does not protect against is in [SECURITY.md](SECURITY.md).

## Why "hal-vault"?

Named for HAL 9000 — a computer that took keeping secrets a little too
seriously. hal-vault has the same dedication to confidentiality, with one
improvement: the pod bay doors (`--reveal`) open whenever *you* ask.

## License

BSD-3-Clause. Copyright (c) 2026 OFOX AI.
