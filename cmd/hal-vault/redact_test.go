package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/ofoxai/hal-vault/vault"
)

// redactAll writes the chunks through a fresh redactor and returns the
// flushed output.
func redactAll(t *testing.T, secrets []string, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	r := newRedactor(&out, secrets)
	for _, c := range chunks {
		n, err := r.Write([]byte(c))
		if err != nil || n != len(c) {
			t.Fatalf("Write(%q) = %d, %v", c, n, err)
		}
	}
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestRedactorMasksSecrets(t *testing.T) {
	secret := testSecret
	mask := vault.Mask(secret)
	got := redactAll(t, []string{secret}, "key="+secret+"\nagain: "+secret+"!\n")
	want := "key=" + mask + "\nagain: " + mask + "!\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Every way of splitting the stream into two or three chunks must still
// mask the secret: a match cut across Write calls is the case a naive
// per-chunk replace misses.
func TestRedactorAcrossChunkBoundaries(t *testing.T) {
	secret := testSecret
	stream := "before " + secret + " middle " + secret + " after"
	want := strings.ReplaceAll(stream, secret, vault.Mask(secret))
	for i := 0; i <= len(stream); i++ {
		for j := i; j <= len(stream); j++ {
			got := redactAll(t, []string{secret}, stream[:i], stream[i:j], stream[j:])
			if got != want {
				t.Fatalf("split at %d,%d: got %q, want %q", i, j, got, want)
			}
		}
	}
}

func TestRedactorByteAtATime(t *testing.T) {
	secret := testSecret
	stream := "x" + secret + secret + "y"
	chunks := strings.Split(stream, "")
	got := redactAll(t, []string{secret}, chunks...)
	want := "x" + vault.Mask(secret) + vault.Mask(secret) + "y"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedactorPassesNearMissesThrough(t *testing.T) {
	secret := testSecret
	// A prefix of the secret that never completes must come out verbatim
	// once the stream ends.
	stream := "prefix " + secret[:10]
	if got := redactAll(t, []string{secret}, stream); got != stream {
		t.Errorf("got %q, want %q", got, stream)
	}
}

func TestRedactorPrefersLongestSecret(t *testing.T) {
	short, long := "abcdefgh", "abcdefgh-ijklmnop"
	got := redactAll(t, []string{short, long}, "["+long+"]["+short+"]")
	want := "[" + vault.Mask(long) + "][" + vault.Mask(short) + "]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedactorIgnoresShortValues(t *testing.T) {
	// Values under minRedactLen characters ("true", "8080") are not masked.
	stream := "port 8080 enabled true"
	if got := redactAll(t, []string{"8080", "true", "12345"}, stream); got != stream {
		t.Errorf("got %q, want %q", got, stream)
	}
	if got := redactAll(t, []string{"123456"}, "id 123456"); got != "id "+vault.Mask("123456") {
		t.Errorf("a %d-character value should be masked: %q", minRedactLen, got)
	}
}

// eachSplit calls fn with stream cut into chunks in many ways: byte at a
// time, and every two- and three-way split.
func eachSplit(stream string, fn func(desc string, chunks []string)) {
	fn("byte at a time", strings.Split(stream, ""))
	for i := 0; i <= len(stream); i++ {
		for j := i; j <= len(stream); j++ {
			fn(fmt.Sprintf("split at %d,%d", i, j), []string{stream[:i], stream[i:j], stream[j:]})
		}
	}
}

// A shorter secret that is a prefix of a longer one must not be masked at a
// Write boundary when the longer secret continues in the next Write:
// masking the prefix early would leave the rest of the longer secret in the
// clear.
func TestRedactorPrefixSecretAcrossBoundary(t *testing.T) {
	long, prefix := "sk-test-AAAA1111BBBB2222", "sk-test-AAAA"
	secrets := []string{long, prefix}

	// The exact sequence from the bug report: the prefix, then the rest.
	got := redactAll(t, secrets, prefix, "1111BBBB2222 end\n")
	if want := vault.Mask(long) + " end\n"; got != want {
		t.Errorf("split at the end of the prefix: got %q, want %q", got, want)
	}

	stream := "a " + long + " b " + prefix + " c " + long
	want := "a " + vault.Mask(long) + " b " + vault.Mask(prefix) + " c " + vault.Mask(long)
	eachSplit(stream, func(desc string, chunks []string) {
		got := redactAll(t, secrets, chunks...)
		if strings.Contains(got, "1111BBBB2222") {
			t.Fatalf("%s: the tail of the longer secret leaked: %q", desc, got)
		}
		if got != want {
			t.Fatalf("%s: got %q, want %q", desc, got, want)
		}
	})

	// A prefix that is never continued is masked as itself at the end.
	if got := redactAll(t, secrets, "x "+prefix); got != "x "+vault.Mask(prefix) {
		t.Errorf("trailing prefix secret at end of stream: got %q", got)
	}
}

// The same for a shorter secret in the middle of a longer one.
func TestRedactorInfixSecret(t *testing.T) {
	long, infix := "sk-live-XXXXinfix123YYYYZZZZ", "infix123"
	secrets := []string{long, infix}
	stream := "a " + long + " b " + infix + " c"
	want := "a " + vault.Mask(long) + " b " + vault.Mask(infix) + " c"
	eachSplit(stream, func(desc string, chunks []string) {
		got := redactAll(t, secrets, chunks...)
		for _, leak := range []string{"XXXX", "YYYYZZZZ", "sk-live-X"} {
			if strings.Contains(got, leak) {
				t.Fatalf("%s: part of the longer secret leaked (%q): %q", desc, leak, got)
			}
		}
		if got != want {
			t.Fatalf("%s: got %q, want %q", desc, got, want)
		}
	})
}

// Two secrets that overlap (the end of one is the start of the other) must
// both be masked completely, not just the one that starts first.
func TestRedactorOverlappingSecrets(t *testing.T) {
	first, second := "abcdefgh12", "gh12-ijklmnop"
	secrets := []string{first, second}
	stream := "x abcdefgh12-ijklmnop y"
	want := "x " + vault.Mask(first) + vault.Mask(second) + " y"
	eachSplit(stream, func(desc string, chunks []string) {
		got := redactAll(t, secrets, chunks...)
		if strings.Contains(got, "ijklmnop") || strings.Contains(got, "abcdef") {
			t.Fatalf("%s: an overlapping secret leaked: %q", desc, got)
		}
		if got != want {
			t.Fatalf("%s: got %q, want %q", desc, got, want)
		}
	})
}
