package main

import (
	"bytes"
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
