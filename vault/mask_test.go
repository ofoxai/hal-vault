package vault

import (
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   string
	}{
		{"empty", "", "(empty)"},
		{"one char", "a", "•••• (1 chars)"},
		{"seven chars", "abcdefg", "•••• (7 chars)"},
		{"eight chars", "abcdefgh", "ab…gh (8 chars)"},
		{"fifteen chars", "abcdefghijklmno", "ab…no (15 chars)"},
		{"sixteen chars", "abcdefghijklmnop", "abcd…mnop (16 chars)"},
		{"long api key", "sk-proj-abcdef1234567890", "sk-p…7890 (24 chars)"},
		{"unicode seven runes", "日本語パスワー", "•••• (7 chars)"},
		{"unicode eleven runes", "héllo wörld", "hé…ld (11 chars)"},
		{"unicode sixteen runes", "密码安全测试一二三四五六七八九十", "密码安全…七八九十 (16 chars)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Mask(tt.secret); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.secret, got, tt.want)
			}
		})
	}
}

func TestMaskNeverContainsFullSecret(t *testing.T) {
	secrets := []string{
		"zq!", "secret!", // n < 8: fully hidden
		"abcdefgh",                 // n == 8
		"abcdefghijklmno",          // n == 15
		"abcdefghijklmnop",         // n == 16
		"sk-proj-abcdef1234567890", // long
		"密码安全测试一二三四五六七八九十",                  // multi-byte runes
		strings.Repeat("x", 100) + "unique", // very long
	}
	for _, s := range secrets {
		masked := Mask(s)
		if strings.Contains(masked, s) {
			t.Errorf("Mask(%q) = %q contains the full secret", s, masked)
		}
	}
}

func TestMaskRevealsAtMostEightRunes(t *testing.T) {
	// For any input, the visible prefix+suffix must never exceed 8 runes.
	for _, s := range []string{
		"abcdefgh",
		"abcdefghijklmno",
		"abcdefghijklmnop",
		strings.Repeat("z", 200),
	} {
		masked := Mask(s)
		// Strip the " (N chars)" suffix and the ellipsis, count what remains.
		core := masked[:strings.LastIndex(masked, " (")]
		visible := strings.ReplaceAll(core, "…", "")
		if n := len([]rune(visible)); n > 8 {
			t.Errorf("Mask(%q) reveals %d runes (%q), want at most 8", s, n, visible)
		}
	}
}

func TestEntryMasked(t *testing.T) {
	e := &Entry{Value: "sk-proj-abcdef1234567890"}
	if got, want := e.Masked(), Mask(e.Value); got != want {
		t.Errorf("Entry.Masked() = %q, want %q", got, want)
	}
}

func TestMaskSanitizesControlCharacters(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{"embedded newlines", "AB\nCDEFGHIJKLM\nYZ"},
		{"leading ANSI escape", "\x1b[31mEVILESCAPE123456"},
		{"tabs and carriage returns", "\tAB\rCDEFGHIJKLMN\r\t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := Mask(tt.secret)
			for _, r := range masked {
				if r == '\n' || r == '\r' || r == '\t' || r == '\x1b' {
					t.Errorf("Mask(%q) = %q contains control character %q", tt.secret, masked, r)
				}
			}
		})
	}
}
