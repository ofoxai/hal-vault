package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ofoxai/hal-vault/vault"
)

const timeFormat = "2006-01-02 15:04"

// entryJSON is the JSON representation of an entry for --json output.
// Value is included only when --reveal is given.
type entryJSON struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Type      string    `json:"type"`
	Tags      []string  `json:"tags"`
	Note      string    `json:"note"`
	Masked    string    `json:"masked"`
	Value     *string   `json:"value,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func entryToJSON(e *vault.Entry, reveal bool) entryJSON {
	tags := e.Tags
	if tags == nil {
		tags = []string{}
	}
	j := entryJSON{
		ID:        e.ID,
		Label:     e.Label,
		Type:      e.Type,
		Tags:      tags,
		Note:      e.Note,
		Masked:    e.Masked(),
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
	if reveal {
		v := e.Value
		j.Value = &v
	}
	return j
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// renderEntries prints entries as an aligned table, or as a JSON array.
// Values are always masked.
func renderEntries(w io.Writer, entries []vault.Entry, asJSON bool) error {
	if asJSON {
		out := make([]entryJSON, 0, len(entries))
		for i := range entries {
			out = append(out, entryToJSON(&entries[i], false))
		}
		return writeJSON(w, out)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTYPE\tLABEL\tTAGS\tMASKED\tUPDATED")
	for i := range entries {
		e := &entries[i]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.ID, e.Type, e.Label, strings.Join(e.Tags, ","),
			e.Masked(), e.UpdatedAt.Local().Format(timeFormat))
	}
	return tw.Flush()
}

// printEntry prints a single entry with metadata; the value is masked.
func printEntry(w io.Writer, e *vault.Entry) {
	fmt.Fprintf(w, "id:      %s\n", e.ID)
	fmt.Fprintf(w, "label:   %s\n", e.Label)
	fmt.Fprintf(w, "type:    %s\n", e.Type)
	if len(e.Tags) > 0 {
		fmt.Fprintf(w, "tags:    %s\n", strings.Join(e.Tags, ", "))
	}
	if e.Note != "" {
		fmt.Fprintf(w, "note:    %s\n", e.Note)
	}
	fmt.Fprintf(w, "value:   %s\n", e.Masked())
	fmt.Fprintf(w, "created: %s\n", e.CreatedAt.Local().Format(timeFormat))
	fmt.Fprintf(w, "updated: %s\n", e.UpdatedAt.Local().Format(timeFormat))
}
