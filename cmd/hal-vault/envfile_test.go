package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseEnvValues(t *testing.T) {
	input := "\uFEFF# a comment\n" +
		"\n" +
		"PLAIN=value\n" +
		"export EXPORTED=yes\n" +
		"\texport\tTABBED=1\n" +
		"SPACED = padded value  \n" +
		"EMPTY=\n" +
		"EMPTY_QUOTED=\"\"\n" +
		"SINGLE='keep # this'  # comment\n" +
		"LITERAL='a\\nb $HOME'\n" +
		"DOUBLE=\"say \\\"hi\\\"\\n\\tdone\\\\\" # trailing comment\n" +
		"INLINE=abc # comment\n" +
		"HASH=abc#def\n" +
		"REF=hal7://openai\n" +
		"exporter=not-a-prefix\n" +
		"CRLF=windows\r\n" +
		"PLAIN=overridden\n"
	got, err := parseEnv(strings.NewReader(input), ".env.tpl")
	if err != nil {
		t.Fatal(err)
	}
	want := []envVar{
		{"PLAIN", "value"},
		{"EXPORTED", "yes"},
		{"TABBED", "1"},
		{"SPACED", "padded value"},
		{"EMPTY", ""},
		{"EMPTY_QUOTED", ""},
		{"SINGLE", "keep # this"},
		{"LITERAL", `a\nb $HOME`},
		{"DOUBLE", "say \"hi\"\n\tdone\\"},
		{"INLINE", "abc"},
		{"HASH", "abc#def"},
		{"REF", "hal7://openai"},
		{"exporter", "not-a-prefix"},
		{"CRLF", "windows"},
		{"PLAIN", "overridden"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseEnv:\n got %q\nwant %q", got, want)
	}
}

func TestParseEnvErrors(t *testing.T) {
	const secretish = "sk-must-not-echo-1234567890"
	for _, tc := range []struct {
		name, input, wantErr string
	}{
		{"no equals", "JUST_A_WORD\n", ".env.tpl:1: expected KEY=VALUE"},
		{"bad key", "OK=1\n1BAD=x\n", ".env.tpl:2: invalid variable name"},
		{"dash in key", "MY-KEY=x\n", "invalid variable name"},
		{"unterminated single", "K='" + secretish + "\n", ".env.tpl:1: K: unterminated single quote"},
		{"unterminated double", "K=\"" + secretish + "\n", ".env.tpl:1: K: unterminated double quote"},
		{"text after quote", "K='" + secretish + "'oops\n", "unexpected text after closing quote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEnv(strings.NewReader(tc.input), ".env.tpl")
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), secretish) {
				t.Errorf("error echoes the value: %q", err)
			}
		})
	}
}
