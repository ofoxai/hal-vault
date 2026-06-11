// Command hal-vault is a simple, modern and secure secret store.
//
// All secrets are kept in a single age-encrypted file, encrypted to an SSH
// public key and decrypted with the matching SSH private key. Output is
// always masked unless --reveal is given, which makes it safe to use from
// scripts and AI agents.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// Version is the release version, set at build time via
// -ldflags "-X main.Version=v1.2.3". When unset, the module version recorded
// in the build info is used instead.
var Version = "(devel)"

const usage = `hal-vault is a simple secret store encrypted with your SSH key.

Usage:
    hal-vault init [-r PUBKEY] [-i PRIVKEY]
    hal-vault add LABEL [-t TYPE] [--tags TAG,...] [-n NOTE]
    hal-vault get ID|LABEL [--reveal] [--json]
    hal-vault list [--json]
    hal-vault search [QUERY] [--tag TAG] [--type TYPE] [--json]
    hal-vault update ID|LABEL [--label LABEL] [-t TYPE] [--tags TAG,...]
                     [-n NOTE] [--value]
    hal-vault rm ID|LABEL [-f]
    hal-vault version

Every command also accepts -d DIR to select the vault directory
(default $HAL_VAULT_DIR, or ~/.hal-vault).

Options:
    -r PUBKEY      SSH public key the vault encrypts to (default
                   ~/.ssh/id_ed25519.pub, or ~/.ssh/id_rsa.pub).
    -i PRIVKEY     Matching SSH private key, used for decryption.
    -t TYPE        Entry type: api_key, password, token, ssh_key, cert,
                   identity, or other (the default).
    --tags TAG,... Comma-separated tags. With update, replaces all tags.
    -n NOTE        Free-form note.
    --reveal       Print the raw secret value instead of the masked one.
    --json         Print JSON instead of the human-readable output.
    --value        With update, read a new secret value like add does.
    -f             Skip the confirmation prompt for rm.

Secret values are never passed as command line arguments: add and
update --value read them from standard input when piped, or from a
hidden interactive prompt on a terminal. Output is always masked
unless --reveal is given.

Examples:
    $ hal-vault init
    $ hal-vault add openai -t api_key --tags ai,prod < openai.key
    added q3k7mp openai: sk-p…7890 (24 chars)
    $ export OPENAI_API_KEY="$(hal-vault get openai --reveal)"
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// errFlagParse signals a flag parsing failure that the flag package has
// already reported on stderr; run exits with code 2 without further output.
var errFlagParse = errors.New("invalid flags")

// usageError is a command line usage mistake; run reports it and exits
// with code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usageErrorf(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// run executes the command line and returns the process exit code:
// 0 on success, 1 on error, 2 on usage error.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		io.WriteString(stderr, usage)
		return 2
	}

	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "help", "-h", "--help":
		io.WriteString(stdout, usage)
	case "version":
		fmt.Fprintln(stdout, version())
	case "init":
		err = cmdInit(rest, stdout, stderr)
	case "add":
		err = cmdAdd(rest, stdin, stdout, stderr)
	case "get":
		err = cmdGet(rest, stdin, stdout, stderr)
	case "list":
		err = cmdList(rest, stdin, stdout, stderr)
	case "search":
		err = cmdSearch(rest, stdin, stdout, stderr)
	case "update":
		err = cmdUpdate(rest, stdin, stdout, stderr)
	case "rm":
		err = cmdRm(rest, stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "hal-vault: unknown command %q\n", cmd)
		io.WriteString(stderr, usage)
		return 2
	}

	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errFlagParse):
		return 2
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(stderr, "hal-vault: %s\n", ue.msg)
		return 2
	}
	fmt.Fprintf(stderr, "hal-vault: %v\n", err)
	return 1
}

func version() string {
	if Version != "(devel)" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok &&
		bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "(devel)"
}
