package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// envVar is one KEY=VALUE assignment.
type envVar struct {
	Key   string
	Value string
}

// readEnvFile parses the dotenv file at path. See parseEnv for the syntax.
func readEnvFile(path string) ([]envVar, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseEnv(f, path)
}

// parseEnv parses a dotenv subset:
//
//	# comment
//	KEY=value            unquoted; trailing " # comment" is stripped
//	export KEY=value     the export prefix is ignored
//	KEY='literal value'  single quotes: taken verbatim
//	KEY="a \"b\"\n"      double quotes: \" \\ \n \r \t escapes
//	KEY=                 empty value
//
// There is no variable expansion and no multi-line values. Errors name the
// file and line but never echo the value, which may be a secret.
func parseEnv(r io.Reader, name string) ([]envVar, error) {
	var vars []envVar
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if n == 1 {
			line = strings.TrimPrefix(line, "\uFEFF") // UTF-8 BOM
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimSpace(rest)
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", name, n)
		}
		key = strings.TrimSpace(key)
		if !validEnvKey(key) {
			return nil, fmt.Errorf("%s:%d: invalid variable name %q", name, n, key)
		}
		value, err := parseEnvValue(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %s: %v", name, n, key, err)
		}
		vars = append(vars, envVar{Key: key, Value: value})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return vars, nil
}

// parseEnvValue parses the right-hand side of an assignment, already
// trimmed of surrounding whitespace.
func parseEnvValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	switch raw[0] {
	case '\'':
		end := strings.IndexByte(raw[1:], '\'')
		if end < 0 {
			return "", fmt.Errorf("unterminated single quote")
		}
		return raw[1 : end+1], checkTrailing(raw[end+2:])
	case '"':
		var b strings.Builder
		for i := 1; i < len(raw); i++ {
			c := raw[i]
			switch {
			case c == '"':
				return b.String(), checkTrailing(raw[i+1:])
			case c == '\\' && i+1 < len(raw):
				i++
				switch raw[i] {
				case 'n':
					b.WriteByte('\n')
				case 'r':
					b.WriteByte('\r')
				case 't':
					b.WriteByte('\t')
				case '"', '\\':
					b.WriteByte(raw[i])
				default:
					b.WriteByte('\\')
					b.WriteByte(raw[i])
				}
			default:
				b.WriteByte(c)
			}
		}
		return "", fmt.Errorf("unterminated double quote")
	default:
		// An unquoted value ends at whitespace followed by '#'.
		for i := 1; i < len(raw); i++ {
			if raw[i] == '#' && (raw[i-1] == ' ' || raw[i-1] == '\t') {
				return strings.TrimSpace(raw[:i]), nil
			}
		}
		return raw, nil
	}
}

// checkTrailing allows only whitespace or a comment after a quoted value.
func checkTrailing(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || s[0] == '#' {
		return nil
	}
	return fmt.Errorf("unexpected text after closing quote")
}

// validEnvKey reports whether k is a portable variable name:
// [A-Za-z_][A-Za-z0-9_]*.
func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, c := range k {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
