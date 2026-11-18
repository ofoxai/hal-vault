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
// the stream with its vault.Mask form before passing it on.
//
// Decisions are made left to right, one position at a time. At each position
// the longest secret that starts there is masked, and the masked region grows
// over any secret that starts inside it and runs past its end (overlapping
// secrets). A position is not decided while the bytes from it to the end of
// the buffer could still grow into a longer secret: that tail is held back
// until a later Write or Flush settles it. So a match is never cut short by
// a Write boundary — whether a secret is split across writes, or a shorter
// secret is a prefix or infix of a longer one.
//
// A redactor is not safe for concurrent use; give each stream its own.
type redactor struct {
	w       io.Writer
	secrets [][]byte // longest first, so the longest match at a position wins
	masks   map[string][]byte
	first   [256]bool // first bytes of the secrets, a fast skip for the rest
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
		r.first[v[0]] = true
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
	out, rest := r.scan(r.pending, false)
	r.pending = append(r.pending[:0], rest...)
	if len(out) > 0 {
		if _, err := r.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush masks and writes out any held-back bytes, matching only what is
// complete. Call it once the stream has ended.
func (r *redactor) Flush() error {
	if len(r.pending) == 0 {
		return nil
	}
	out, _ := r.scan(r.pending, true)
	r.pending = r.pending[:0]
	_, err := r.w.Write(out)
	return err
}

// scan masks buf and splits the result into the part that is decided and
// the undecided tail to hold back. With final set, everything is decided.
func (r *redactor) scan(buf []byte, final bool) (out, rest []byte) {
	for i := 0; i < len(buf); {
		end, masks, hold := r.matchAt(buf, i, final)
		switch {
		case hold:
			return out, buf[i:]
		case end < 0:
			out = append(out, buf[i])
			i++
		default:
			for _, m := range masks {
				out = append(out, m...)
			}
			i = end
		}
	}
	return out, nil
}

// matchAt decides position i of buf. It returns the end of the masked
// region and its masks, end < 0 when no secret starts at i, or hold when
// the outcome depends on bytes not yet written.
func (r *redactor) matchAt(buf []byte, i int, final bool) (end int, masks [][]byte, hold bool) {
	if !final && r.partial(buf[i:]) {
		return 0, nil, true
	}
	s := r.longestAt(buf[i:])
	if s == nil {
		return -1, nil, false
	}
	end, masks = i+len(s), [][]byte{r.masks[string(s)]}
	// Extend over secrets that start inside the region and end past it,
	// so no part of an overlapping secret is left in the clear.
	for j := i + 1; j < end; j++ {
		if !final && r.partial(buf[j:]) {
			return 0, nil, true
		}
		if t := r.longestAt(buf[j:]); t != nil && j+len(t) > end {
			end = j + len(t)
			masks = append(masks, r.masks[string(t)])
		}
	}
	return end, masks, false
}

// longestAt returns the longest secret that b starts with, or nil.
func (r *redactor) longestAt(b []byte) []byte {
	if len(b) == 0 || !r.first[b[0]] {
		return nil
	}
	for _, s := range r.secrets {
		if bytes.HasPrefix(b, s) {
			return s
		}
	}
	return nil
}

// partial reports whether b — the rest of the buffer — is a proper prefix of
// some secret, i.e. more bytes could still complete a match starting here.
func (r *redactor) partial(b []byte) bool {
	if len(b) == 0 || len(b) >= r.maxLen || !r.first[b[0]] {
		return false
	}
	for _, s := range r.secrets {
		if len(s) > len(b) && bytes.HasPrefix(s, b) {
			return true
		}
	}
	return false
}
