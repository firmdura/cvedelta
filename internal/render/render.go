// SPDX-License-Identifier: Apache-2.0

// Package render writes complete schema-1 reports without interpreting source
// status labels or adding evidence. Writers validate before emitting any bytes.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/firmdura/cvedelta/internal/model"
)

// WriteJSON writes deterministic, indented schema-1 JSON and a final newline.
// The result can be decoded with encoding/json into model.Report. Absent source
// attributes remain absent; present strings, including empty strings, are exact.
// Records and component version changes are sorted without mutating report.
func WriteJSON(w io.Writer, report model.Report) error {
	r, err := prepare(report)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("render JSON: %w", err)
	}
	return write(w, append(data, '\n'))
}

// WriteMarkdown writes every report field as safe, deterministic Markdown.
// Untrusted strings are quoted in code spans, with controls and code/table/HTML
// delimiters escaped visibly. Source links remain inert text. No findings
// or attributes are truncated. Use JSON when exact machine-readable text is needed.
func WriteMarkdown(w io.Writer, report model.Report) error {
	r, err := prepare(report)
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# CVEDelta observed finding report\n\n")
	fmt.Fprintf(&b, "Schema version: %d\n\nComparable: %t\n\nDecision: %s\n\n", r.SchemaVersion, r.Comparable, r.Decision)
	b.WriteString("The decision describes comparison and selected change gating, not a security assessment.\n\n")
	b.WriteString("Provenance is caller-supplied, not independently attested. Matching provenance is necessary for comparability; it does not prove completeness, truth or applicability.\n\n")
	b.WriteString("Statuses are literal producer claims. Patched and Ignored are not independent evidence of remediation, applicability or compliance. no_longer_reported means absence from the candidate report and does not establish a fix.\n\n")
	b.WriteString("Quoted values are inert code text. Backslash escapes show newlines, controls, formatting characters and code/table/HTML delimiters; an empty quoted value differs from an absent attribute.\n\n")
	b.WriteString("## Comparability reasons\n\n")
	if len(r.Reasons) == 0 {
		b.WriteString("None. The stated provenance comparability conditions match.\n\n")
	} else {
		for _, reason := range r.Reasons {
			fmt.Fprintf(&b, "- %s: %s\n", reason.Code, quote(reason.Message))
		}
		b.WriteString("\nObserved changes below remain available, but this report is incomparable. Change gating cannot override incomparability.\n\n")
	}
	writeMetadata(&b, "Baseline provenance", r.Baseline)
	writeMetadata(&b, "Candidate provenance", r.Candidate)
	b.WriteString("## Selected change policy\n\n")
	if len(r.Policy.FailOn) == 0 {
		b.WriteString("fail_on: none (change gating disabled; incomparability still applies).\n\n")
	} else {
		fmt.Fprintf(&b, "fail_on: %s\n\n", categories(r.Policy.FailOn))
	}
	b.WriteString("## Finding counts\n\n| Category | Count |\n| --- | ---: |\n")
	for i, c := range allCategories {
		fmt.Fprintf(&b, "| %s | %d |\n", c, countValues(r.Counts)[i])
	}
	fmt.Fprintf(&b, "\nTotal finding records: %d\n\n", len(r.Records))
	b.WriteString("## Component version changes\n\n")
	if len(r.ComponentVersionChanges) == 0 {
		b.WriteString("None.\n\n")
	} else {
		b.WriteString("| Layer | Component | Baseline version | Candidate version |\n| --- | --- | --- | --- |\n")
		for _, c := range r.ComponentVersionChanges {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", quote(c.Component.Layer), quote(c.Component.Name), quote(c.Before), quote(c.After))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Finding records\n\n")
	if len(r.Records) == 0 {
		b.WriteString("No finding records. This is an observed report result, not proof of vulnerability absence.\n")
	}
	for i, row := range r.Records {
		fmt.Fprintf(&b, "### Record %d\n\n", i+1)
		fmt.Fprintf(&b, "- Layer: %s\n- Component: %s\n- CVE ID: %s\n- Category: %s\n", quote(row.Component.Layer), quote(row.Component.Name), row.CVEID, row.Category)
		if row.AbsenceReason == nil {
			b.WriteString("- Absence reason: none (both contexts present)\n")
		} else {
			fmt.Fprintf(&b, "- Absence reason for missing %s context: %s\n", missingSide(row), *row.AbsenceReason)
		}
		if len(row.ChangedFields) == 0 {
			b.WriteString("- Changed fields: none\n\n")
		} else {
			fmt.Fprintf(&b, "- Changed fields: %s\n\n", strings.Join(row.ChangedFields, ", "))
		}
		writeContext(&b, "Baseline context", row.Before)
		writeContext(&b, "Candidate context", row.After)
	}
	return write(w, []byte(strings.TrimRight(b.String(), "\n")+"\n"))
}

func write(w io.Writer, data []byte) error {
	if w == nil {
		return fmt.Errorf("render: nil writer")
	}
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("render output: %w", io.ErrShortWrite)
	}
	return nil
}

func prepare(r model.Report) (model.Report, error) {
	if err := validate(r); err != nil {
		return model.Report{}, fmt.Errorf("render report: %w", err)
	}
	// Only these outer lists are reordered; no caller-owned slice is modified.
	r.Records = append([]model.Record{}, r.Records...)
	sort.Slice(r.Records, func(i, j int) bool {
		a, b := r.Records[i], r.Records[j]
		if a.Component != b.Component {
			return componentLess(a.Component, b.Component)
		}
		return a.CVEID < b.CVEID
	})
	r.ComponentVersionChanges = append([]model.ComponentVersionChange{}, r.ComponentVersionChanges...)
	sort.Slice(r.ComponentVersionChanges, func(i, j int) bool {
		return componentLess(r.ComponentVersionChanges[i].Component, r.ComponentVersionChanges[j].Component)
	})
	return r, nil
}

func componentLess(a, b model.ComponentID) bool {
	if a.Layer != b.Layer {
		return a.Layer < b.Layer
	}
	return a.Name < b.Name
}

// The payload cannot close its code span or split a table cell. Code spans also
// keep URLs inert in Markdown engines that linkify decoded ordinary text.
func quote(s string) string {
	var visible strings.Builder
	visible.WriteString("`\"")
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			switch r {
			case '\n':
				visible.WriteString(`\n`)
			case '\r':
				visible.WriteString(`\r`)
			case '\t':
				visible.WriteString(`\t`)
			default:
				fmt.Fprintf(&visible, `\u{%X}`, r)
			}
		} else {
			switch r {
			case '\\':
				visible.WriteString(`\\`)
			case '"':
				visible.WriteString(`\"`)
			case '`', '|', '<', '>', '&':
				fmt.Fprintf(&visible, `\u{%X}`, r)
			default:
				visible.WriteRune(r)
			}
		}
	}
	visible.WriteString("\"`")
	return visible.String()
}

func writeMetadata(b *strings.Builder, heading string, m model.Metadata) {
	fmt.Fprintf(b, "## %s\n\n", heading)
	fmt.Fprintf(b, "- schema_version: %d\n- report_sha256: %s\n", m.SchemaVersion, quote(m.ReportSHA256))
	fmt.Fprintf(b, "- firmware.configuration_id: %s\n- firmware.build_id: %s\n- firmware.source_revision: %s\n", quote(m.Firmware.ConfigurationID), quote(m.Firmware.BuildID), quote(m.Firmware.SourceRevision))
	fmt.Fprintf(b, "- scanner.name: %s\n- scanner.revision: %s\n", quote(m.Scanner.Name), quote(m.Scanner.Revision))
	fmt.Fprintf(b, "- database.sha256: %s\n- coverage.scope_sha256: %s\n- coverage.complete: %t\n\n", quote(m.Database.SHA256), quote(m.Coverage.ScopeSHA256), m.Coverage.Complete)
}

func writeContext(b *strings.Builder, heading string, c *model.Context) {
	fmt.Fprintf(b, "#### %s\n\n", heading)
	if c == nil {
		b.WriteString("Absent.\n\n")
		return
	}
	fmt.Fprintf(b, "- Version: %s\n- Reported status: %s\n", quote(c.Version), c.Status)
	found := false
	for _, a := range attributes(c.Attributes) {
		if a.value != nil {
			fmt.Fprintf(b, "- %s: %s\n", a.name, quote(*a.value))
			found = true
		}
	}
	if !found {
		b.WriteString("- Recognized attributes: none present\n")
	}
	b.WriteString("\n")
}

func missingSide(r model.Record) string {
	if r.Before == nil {
		return "baseline"
	}
	return "candidate"
}

func categories(values []model.Category) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = string(v)
	}
	return strings.Join(parts, ", ")
}
