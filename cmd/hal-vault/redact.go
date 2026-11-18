package main

import (
	"bytes"
	"io"
	"sort"
	"unicode/utf8"

	"github.com/ofoxai/hal-vault/vault"
)

// minRedactLen is the shortest secret (in characters) that run masks in a
// child's output. Shorter values — "true", "8080", "dev" — would mangle
// ordinary output far more often than they would protect anything.
const minRedactLen = 6

// redactor is an io.Writer that replaces every occurrence of a secret in
// the stream with its vault.Mask form before passing it on. Matches split
// across Write calls are still caught: a trailing chunk that could be the
// start of a secret is held back until the next Write or Flush decides it.
//
// A redactor is not safe for concurrent use; give each stream its own.
type redactor struct {
	w       io.Writer
	secrets [][]byte // longest first, so overlapping secrets mask maximally
	masks   map[string][]byte
	maxLen  int
	pending []byte
}

// newRedactor returns a redactor for the given secret values. Values shorter
// than minRedactLen characters are ignored.
func newRedactor(w io.Writer, values []string) *redactor {
	r := &redactor{w: w, masks: make(map[string][]byte)}
	for _, v := range values {
		if utf8.RuneCountInString(v) < minRedactLen {
			continue
		}
		if _, dup := r.masks[v]; dup {
			continue
		}
		r.masks[v] = []byte(vault.Mask(v))
		r.secrets = append(r.secrets, []byte(v))
		r.maxLen = max(r.maxLen, len(v))
	}
	sort.SliceStable(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	return r
}

// Write masks p and forwards what can be decided now. It always reports
// len(p) on success, as io.Writer requires.
func (r *redactor) Write(p []byte) (int, error) {
	if len(r.secrets) == 0 {
		return r.w.Write(p)
	}
	r.pending = append(r.pending, p...)
	out, rest := r.scan(r.pending)
	r.pending = append(r.pending[:0], rest...)
	if len(out) > 0 {
		if _, err := r.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush writes out any held-back bytes. Call it once the stream has ended.
func (r *redactor) Flush() error {
	if len(r.pending) == 0 {
		return nil
	}
	_, err := r.w.Write(r.pending)
	r.pending = r.pending[:0]
	return err
}

// scan masks every complete secret in buf and splits the result into the
// part that can be written now and a held-back tail: the longest suffix of
// buf that is a proper prefix of some secret.
func (r *redactor) scan(buf []byte) (out, rest []byte) {
	for {
		at, s := r.firstMatch(buf)
		if s == nil {
			break
		}
		out = append(out, buf[:at]...)
		out = append(out, r.masks[string(s)]...)
		buf = buf[at+len(s):]
	}
	hold := r.partialSuffix(buf)
	out = append(out, buf[:len(buf)-hold]...)
	return out, buf[len(buf)-hold:]
}

// firstMatch returns the earliest complete secret in buf (the longest one
// at that position) and its offset, or nil.
func (r *redactor) firstMatch(buf []byte) (int, []byte) {
	best, bestAt := []byte(nil), -1
	for _, s := range r.secrets {
		if i := bytes.Index(buf, s); i >= 0 && (bestAt < 0 || i < bestAt) {
			best, bestAt = s, i
		}
	}
	return bestAt, best
}

// partialSuffix returns the length of the longest suffix of buf that is a
// proper prefix of a secret — the bytes that a later Write may complete.
func (r *redactor) partialSuffix(buf []byte) int {
	for n := min(len(buf), r.maxLen-1); n > 0; n-- {
		tail := buf[len(buf)-n:]
		for _, s := range r.secrets {
			if len(s) > n && bytes.HasPrefix(s, tail) {
				return n
			}
		}
	}
	return 0
}
