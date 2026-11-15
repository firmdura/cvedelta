// SPDX-License-Identifier: Apache-2.0

package cvedelta_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/cvedelta/pkg/cvedelta"
)

func input(t *testing.T, report, metadata string) cvedelta.Input {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "provenance", "synthetic", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	raw := read(report)
	in, err := cvedelta.ReadInput(bytes.NewReader(raw), bytes.NewReader(read(metadata)))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if !in.Valid() || in.RawSHA256() != hex.EncodeToString(hash[:]) {
		t.Fatal("successful public input was not bound to the raw bytes")
	}
	return in
}

func TestPublicComparisonAndRoundTrip(t *testing.T) {
	before := input(t, "baseline.json", "baseline.meta.json")
	after := input(t, "candidate.json", "candidate.meta.json")
	report, err := cvedelta.Compare(before, after, cvedelta.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != cvedelta.ChangesDetected || !report.Comparable || len(report.Records) != 10 {
		t.Fatalf("unexpected public report: %+v", report)
	}
	var encoded bytes.Buffer
	if err := cvedelta.WriteJSON(&encoded, report); err != nil {
		t.Fatal(err)
	}
	var decoded cvedelta.Report
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report, decoded) {
		t.Fatal("public JSON decode changed report fields")
	}
	for _, row := range decoded.Records {
		if row.Category == cvedelta.NoLongerReported {
			if row.Before == nil || row.Before.Status != cvedelta.Patched || row.After != nil || row.AbsenceReason == nil {
				t.Fatalf("disappearance lost observed context: %+v", row)
			}
		}
	}
	var markdown bytes.Buffer
	if err := cvedelta.WriteMarkdown(&markdown, decoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(markdown.String(), "no_longer_reported") || !strings.Contains(markdown.String(), "does not establish a fix") {
		t.Fatal("Markdown lost disappearance semantics")
	}
	// These declarations exercise public construction of nested output types.
	var _ cvedelta.Delta = decoded.Delta
	var _ cvedelta.Policy = decoded.Policy
	var _ cvedelta.Metadata = before.Metadata()
	var _ cvedelta.Document = before.Document()
	var _ cvedelta.Record = decoded.Records[0]
	var _ cvedelta.ComponentID = decoded.Records[0].Component
	var _ cvedelta.Context = *decoded.Records[0].After
	var _ cvedelta.Attributes = decoded.Records[0].After.Attributes
	var _ cvedelta.Category = cvedelta.New
	var _ cvedelta.Decision = cvedelta.Clean
}

func TestInputAndReturnedReportsAreDetached(t *testing.T) {
	before := input(t, "baseline.json", "baseline.meta.json")
	after := input(t, "candidate.json", "candidate.meta.json")
	expected, err := cvedelta.Compare(before, after, cvedelta.Options{})
	if err != nil {
		t.Fatal(err)
	}
	document := before.Document()
	document.Components[0].Name = "tampered"
	*document.Components[0].Issues[0].Detail = "tampered"
	document.Components[0].Issues = nil
	metadata := before.Metadata()
	metadata.Firmware.ConfigurationID = "tampered"
	observed, err := cvedelta.Compare(before, after, cvedelta.Options{})
	if err != nil || !reflect.DeepEqual(expected, observed) {
		t.Fatal("mutating exported input values changed comparison", err)
	}
	for _, row := range observed.Records {
		if row.Before != nil && row.Before.Attributes.Detail != nil {
			*row.Before.Attributes.Detail = "tampered returned report"
		}
	}
	observed.Records[0].Component.Name = "tampered returned report"
	again, err := cvedelta.Compare(before, after, cvedelta.Options{})
	if err != nil || !reflect.DeepEqual(expected, again) {
		t.Fatal("mutating returned report changed immutable input", err)
	}
}

func TestPublicPolicyAndInvalidEvidence(t *testing.T) {
	before := input(t, "baseline.json", "baseline.meta.json")
	after := input(t, "candidate.json", "candidate.meta.json")
	incomparable := input(t, "candidate.json", "database.meta.json")
	for _, tc := range []struct {
		name     string
		after    cvedelta.Input
		options  cvedelta.Options
		decision cvedelta.Decision
	}{
		{"identical", before, cvedelta.Options{}, cvedelta.Clean},
		{"default", after, cvedelta.Options{}, cvedelta.ChangesDetected},
		{"none", after, cvedelta.Options{FailOn: []cvedelta.Category{}}, cvedelta.Clean},
		{"database beats none", incomparable, cvedelta.Options{FailOn: []cvedelta.Category{}}, cvedelta.Incomparable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := cvedelta.Compare(before, tc.after, tc.options)
			if err != nil || r.Decision != tc.decision {
				t.Fatalf("decision %q, error %v", r.Decision, err)
			}
		})
	}
	for _, tc := range []struct {
		name          string
		before, after cvedelta.Input
		options       cvedelta.Options
	}{
		{"zero baseline", cvedelta.Input{}, after, cvedelta.Options{}},
		{"zero candidate", before, cvedelta.Input{}, cvedelta.Options{}},
		{"configuration", before, input(t, "candidate.json", "configuration-mismatch.meta.json"), cvedelta.Options{FailOn: []cvedelta.Category{}}},
		{"invalid option incomparable", before, incomparable, cvedelta.Options{FailOn: []cvedelta.Category{cvedelta.Unchanged}}},
		{"duplicate options", before, after, cvedelta.Options{FailOn: []cvedelta.Category{cvedelta.New, cvedelta.New}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := cvedelta.Compare(tc.before, tc.after, tc.options)
			if err == nil || !reflect.DeepEqual(r, cvedelta.Report{}) {
				t.Fatalf("invalid public comparison returned report: %+v, %v", r, err)
			}
		})
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestPublicErrorsPreserveIdentityAndTypes(t *testing.T) {
	sentinel := errors.New("stream sentinel")
	for _, tc := range []struct{ report, metadata io.Reader }{
		{errorReader{sentinel}, strings.NewReader("{}")},
		{strings.NewReader(`{"version":"1","package":[]}`), errorReader{sentinel}},
	} {
		in, err := cvedelta.ReadInput(tc.report, tc.metadata)
		if !errors.Is(err, sentinel) || in.Valid() {
			t.Fatalf("reader error identity lost: %v", err)
		}
	}
	_, err := cvedelta.ReadInput(strings.NewReader(`{"version":@}`), strings.NewReader("{}"))
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("JSON error type lost: %v", err)
	}
	before := input(t, "baseline.json", "baseline.meta.json")
	report, err := cvedelta.Compare(before, before, cvedelta.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, write := range []func(io.Writer, cvedelta.Report) error{cvedelta.WriteJSON, cvedelta.WriteMarkdown} {
		if err := write(errorWriter{sentinel}, report); !errors.Is(err, sentinel) {
			t.Fatalf("writer error identity lost: %v", err)
		}
		if err := write(shortWriter{}, report); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write identity lost: %v", err)
		}
		var output bytes.Buffer
		if err := write(&output, cvedelta.Report{}); err == nil || output.Len() != 0 {
			t.Fatal("invalid report published output")
		}
	}
}

func TestPublicReadInputTrailingSyntaxErrors(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "provenance", "synthetic", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, stream := range []string{"report", "metadata"} {
		for _, tc := range []struct {
			name, suffix  string
			syntax        bool
			unexpectedEOF bool
		}{
			{"malformed", " \ngarbage", true, false},
			{"incomplete", ` "unfinished`, false, true},
			{"second document", ` null`, false, false},
		} {
			t.Run(stream+"/"+tc.name, func(t *testing.T) {
				raw, meta := read("baseline.json"), read("baseline.meta.json")
				if stream == "report" {
					raw = append(raw, tc.suffix...)
				} else {
					meta = append(meta, tc.suffix...)
				}
				input, err := cvedelta.ReadInput(bytes.NewReader(raw), bytes.NewReader(meta))
				if err == nil || input.Valid() {
					t.Fatalf("public invalid suffix accepted: valid=%v, err=%v", input.Valid(), err)
				}
				var syntax *json.SyntaxError
				if errors.As(err, &syntax) != tc.syntax || errors.Is(err, io.ErrUnexpectedEOF) != tc.unexpectedEOF {
					t.Fatalf("public JSON error type/identity lost or fabricated: %v", err)
				}
				if !strings.HasPrefix(err.Error(), stream+":") {
					t.Fatalf("public invalid suffix lost structural location: %v", err)
				}
			})
		}
	}
}
