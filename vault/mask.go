package vault

import (
	"fmt"
	"unicode"
)

// Mask returns a masked representation of secret that is safe to display.
// It never reveals more than 8 runes of the original value, and control
// characters (newlines, terminal escapes) are replaced with '?' so masked
// output cannot inject extra lines or escape sequences into a terminal,
// table or log.
//
// Rules (n is the rune count of secret):
//
//	n == 0       → "(empty)"
//	n < 8        → "•••• (N chars)"
//	8 ≤ n < 16   → first 2 runes + "…" + last 2 runes + " (N chars)"
//	n ≥ 16       → first 4 runes + "…" + last 4 runes + " (N chars)"
func Mask(secret string) string {
	runes := []rune(secret)
	n := len(runes)
	switch {
	case n == 0:
		return "(empty)"
	case n < 8:
		return fmt.Sprintf("•••• (%d chars)", n)
	case n < 16:
		return fmt.Sprintf("%s…%s (%d chars)", sanitize(runes[:2]), sanitize(runes[n-2:]), n)
	default:
		return fmt.Sprintf("%s…%s (%d chars)", sanitize(runes[:4]), sanitize(runes[n-4:]), n)
	}
}

// sanitize replaces control and other non-printable runes with '?'.
func sanitize(runes []rune) string {
	out := make([]rune, len(runes))
	for i, r := range runes {
		if unicode.IsPrint(r) {
			out[i] = r
		} else {
			out[i] = '?'
		}
	}
	return string(out)
}
