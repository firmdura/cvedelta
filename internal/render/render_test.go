// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/firmdura/cvedelta/internal/model"
)

var fixtures = []string{"report-changes", "report-none", "report-incomparable", "report-unchanged", "report-incomparable-unchanged"}

func load(t *testing.T, name string) model.Report {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "provenance", "synthetic", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var r model.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFrozenReports(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			r := load(t, name)
			original, _ := json.Marshal(r)
			for _, format := range []struct {
				ext   string
				write func(io.Writer, model.Report) error
			}{{"json", WriteJSON}, {"md", WriteMarkdown}} {
				var got bytes.Buffer
				if err := format.write(&got, r); err != nil {
					t.Fatal(err)
				}
				want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "render", name+"."+format.ext))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want) {
					t.Fatalf("%s golden differs", format.ext)
				}
				if !bytes.HasSuffix(got.Bytes(), []byte("\n")) || bytes.HasSuffix(got.Bytes(), []byte("\n\n")) {
					t.Fatalf("%s must end with exactly one newline", format.ext)
				}
				var again bytes.Buffer
				if err := format.write(&again, r); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), again.Bytes()) {
					t.Fatal("nondeterministic rendering")
				}
				if format.ext == "json" {
					var roundtrip model.Report
					decoder := json.NewDecoder(bytes.NewReader(got.Bytes()))
					decoder.DisallowUnknownFields()
					if err := decoder.Decode(&roundtrip); err != nil {
						t.Fatal(err)
					}
					if err := decoder.Decode(new(any)); err != io.EOF {
						t.Fatalf("trailing JSON: %v", err)
					}
					if !reflect.DeepEqual(r, roundtrip) {
						t.Fatal("JSON lost report data")
					}
				}
			}
			after, _ := json.Marshal(r)
			if !bytes.Equal(original, after) {
				t.Fatal("rendering mutated report")
			}
		})
	}
}

func TestCanonicalOrderWithoutMutation(t *testing.T) {
	r := load(t, "report-changes")
	var expectedJSON, expectedMarkdown bytes.Buffer
	if err := WriteJSON(&expectedJSON, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&expectedMarkdown, r); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(r.Records)
	slices.Reverse(r.ComponentVersionChanges)
	firstRecord, firstChange := r.Records[0], r.ComponentVersionChanges[0]
	var gotJSON, gotMarkdown bytes.Buffer
	if err := WriteJSON(&gotJSON, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&gotMarkdown, r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expectedJSON.Bytes(), gotJSON.Bytes()) || !bytes.Equal(expectedMarkdown.Bytes(), gotMarkdown.Bytes()) {
		t.Fatal("output is not canonical")
	}
	if !reflect.DeepEqual(r.Records[0], firstRecord) || !reflect.DeepEqual(r.ComponentVersionChanges[0], firstChange) {
		t.Fatal("sort mutated caller slices")
	}
}

func TestPrepareReusesOrderedLists(t *testing.T) {
	for _, reversed := range []string{"neither", "records", "versions"} {
		t.Run(reversed, func(t *testing.T) {
			r := load(t, "report-changes")
			if reversed == "records" {
				slices.Reverse(r.Records)
			}
			if reversed == "versions" {
				slices.Reverse(r.ComponentVersionChanges)
			}
			got, err := prepare(r)
			if err != nil {
				t.Fatal(err)
			}
			if copied := &got.Records[0] != &r.Records[0]; copied != (reversed == "records") {
				t.Errorf("records copied: %t", copied)
			}
			if copied := &got.ComponentVersionChanges[0] != &r.ComponentVersionChanges[0]; copied != (reversed == "versions") {
				t.Errorf("component version changes copied: %t", copied)
			}
		})
	}
}

func TestInvalidReportsWriteNothing(t *testing.T) {
	badUTF8 := string([]byte{0xff})
	cases := []struct {
		name   string
		change func(*model.Report)
	}{
		{"zero", func(r *model.Report) { *r = model.Report{} }},
		{"schema", func(r *model.Report) { r.SchemaVersion = 2 }},
		{"metadata schema", func(r *model.Report) { r.Baseline.SchemaVersion = 2 }},
		{"metadata checksum", func(r *model.Report) { r.Baseline.ReportSHA256 = "a" }},
		{"metadata scanner", func(r *model.Report) { r.Candidate.Scanner.Name = "other" }},
		{"metadata blank", func(r *model.Report) { r.Candidate.Firmware.BuildID = " \n" }},
		{"metadata utf8", func(r *model.Report) { r.Candidate.Firmware.BuildID = badUTF8 }},
		{"configuration mismatch", func(r *model.Report) { r.Candidate.Firmware.ConfigurationID += "other" }},
		{"nil records", func(r *model.Report) { r.Records = nil }},
		{"nil reasons", func(r *model.Report) { r.Reasons = nil }},
		{"nil versions", func(r *model.Report) { r.ComponentVersionChanges = nil }},
		{"unresolved policy", func(r *model.Report) { r.Policy.FailOn = nil }},
		{"unknown policy", func(r *model.Report) { r.Policy.FailOn = []model.Category{"bad"} }},
		{"unchanged policy", func(r *model.Report) { r.Policy.FailOn = []model.Category{model.Unchanged} }},
		{"duplicate policy", func(r *model.Report) { r.Policy.FailOn = []model.Category{model.New, model.New} }},
		{"policy order", func(r *model.Report) { r.Policy.FailOn = []model.Category{model.ContextChanged, model.New} }},
		{"missing decision", func(r *model.Report) { r.Decision = "" }},
		{"wrong decision", func(r *model.Report) { r.Decision = model.Clean }},
		{"unknown decision", func(r *model.Report) { r.Decision = "passed" }},
		{"false incomparable", func(r *model.Report) { r.Comparable = false; r.Decision = model.Incomparable }},
		{"missing provenance reason", func(r *model.Report) { r.Candidate.Coverage.Complete = false }},
		{"spurious reason", func(r *model.Report) { r.Reasons = []model.Reason{{Code: model.DatabaseChanged, Message: "Different"}} }},
		{"duplicate row", func(r *model.Report) { r.Records = append(r.Records, r.Records[0]); r.Counts.New++ }},
		{"blank layer", func(r *model.Report) { r.Records[0].Component.Layer = " " }},
		{"invalid cve", func(r *model.Report) { r.Records[0].CVEID = "cve-2099-0001" }},
		{"unknown category", func(r *model.Report) { r.Records[0].Category = "fixed" }},
		{"unknown status", func(r *model.Report) { r.Records[0].After.Status = "fixed" }},
		{"blank version", func(r *model.Report) { r.Records[0].After.Version = "\t" }},
		{"attribute utf8", func(r *model.Report) { r.Records[0].After.Attributes.Summary = &badUTF8 }},
		{"new with before", func(r *model.Report) { r.Records[0].Before = r.Records[0].After }},
		{"new missing after", func(r *model.Report) { r.Records[0].After = nil }},
		{"no longer with after", func(r *model.Report) { r.Records[2].After = r.Records[2].Before }},
		{"no absence reason", func(r *model.Report) { r.Records[0].AbsenceReason = nil }},
		{"bad absence reason", func(r *model.Report) { a := model.AbsenceReason("fixed"); r.Records[0].AbsenceReason = &a }},
		{"changed fields nil", func(r *model.Report) { r.Records[0].ChangedFields = nil }},
		{"single side fields", func(r *model.Report) { r.Records[0].ChangedFields = []string{"status"} }},
		{"both missing context", func(r *model.Report) { r.Records[1].Before = nil }},
		{"both absence reason", func(r *model.Report) { r.Records[1].AbsenceReason = r.Records[0].AbsenceReason }},
		{"dropped context change", func(r *model.Report) { r.Records[1].ChangedFields = []string{"status"} }},
		{"field order", func(r *model.Report) { r.Records[1].ChangedFields = []string{"status", "version", "detail"} }},
		{"wrong context category", func(r *model.Report) { r.Records[1].Category = model.ContextChanged }},
		{"wrong unchanged", func(r *model.Report) { r.Records[5].After.Status = model.Patched }},
		{"wrong count", func(r *model.Report) { r.Counts.Unchanged++ }},
		{"negative count", func(r *model.Report) { r.Counts.New = -1 }},
		{"duplicate version", func(r *model.Report) {
			r.ComponentVersionChanges = append(r.ComponentVersionChanges, r.ComponentVersionChanges[0])
		}},
		{"missing version change", func(r *model.Report) { r.ComponentVersionChanges = r.ComponentVersionChanges[1:] }},
		{"empty version change", func(r *model.Report) { r.ComponentVersionChanges[1].After = "" }},
		{"no version change", func(r *model.Report) { r.ComponentVersionChanges[1].After = r.ComponentVersionChanges[1].Before }},
		{"contradictory version", func(r *model.Report) { r.ComponentVersionChanges[0].Before = "0" }},
		{"contradictory component absence", func(r *model.Report) { a := model.ComponentAbsent; r.Records[2].AbsenceReason = &a }},
		{"contradictory component context", func(r *model.Report) { r.Records[2].Before.Version = "0" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := load(t, "report-changes")
			tc.change(&r)
			for _, f := range []func(io.Writer, model.Report) error{WriteJSON, WriteMarkdown} {
				var b bytes.Buffer
				if err := f(&b, r); err == nil {
					t.Fatal("invalid report accepted")
				}
				if b.Len() != 0 {
					t.Fatal("invalid report published partial bytes")
				}
			}
		})
	}
}

func TestReasonValidationAndPreservation(t *testing.T) {
	for _, mutate := range []func(*model.Report){
		func(r *model.Report) { r.Reasons[0].Message = " \n\t" },
		func(r *model.Report) { r.Reasons[0].Message = string([]byte{0xff}) },
		func(r *model.Report) { r.Reasons[0].Code = "unknown" },
		func(r *model.Report) { slices.Reverse(r.Reasons) },
		func(r *model.Report) { r.Reasons = r.Reasons[:1] },
		func(r *model.Report) { r.Reasons = append(r.Reasons, r.Reasons[0]) },
		func(r *model.Report) { r.Policy.FailOn = []model.Category{}; r.Decision = model.Clean },
	} {
		r := load(t, "report-incomparable")
		mutate(&r)
		for _, f := range []func(io.Writer, model.Report) error{WriteJSON, WriteMarkdown} {
			var b bytes.Buffer
			if err := f(&b, r); err == nil || b.Len() != 0 {
				t.Fatal("invalid reason/report accepted or emitted bytes")
			}
		}
	}
}

func TestHostileTextIsLosslessJSONAndInertMarkdown(t *testing.T) {
	payload := "<script>alert('x')</script>|`fence`\n# fake heading\r\n[click](javascript:alert(1)) ![image](https://example.invalid) https://evil.invalid www.evil.invalid <a@evil.invalid> &lt;img&gt; \\n \\u{1B}\x1b[31m\x00\x07\t\u0085\u2028\u2029\u202E\u2066" + strings.Repeat("ALL-TEXT-RETAINED", 4096)
	r := load(t, "report-incomparable-unchanged")
	r.Reasons[0].Message = payload
	r.Baseline.Firmware.ConfigurationID = payload
	r.Candidate.Firmware.ConfigurationID = payload
	r.Baseline.Firmware.BuildID = payload
	r.Candidate.Firmware.SourceRevision = payload
	r.Baseline.Scanner.Revision = payload
	r.Candidate.Scanner.Revision = payload
	r.Records = r.Records[len(r.Records)-1:]
	r.Counts = model.Counts{Unchanged: 1}
	row := &r.Records[0]
	row.Component = model.ComponentID{Layer: payload, Name: payload}
	row.Before.Version, row.After.Version = payload, payload
	all := model.Attributes{Detail: &payload, Description: &payload, Summary: &payload, Link: &payload, Modified: &payload, ScoreV2: &payload, ScoreV3: &payload, ScoreV4: &payload, Vector: &payload, VectorString: &payload}
	row.Before.Attributes, row.After.Attributes = all, all
	var j, m bytes.Buffer
	if err := WriteJSON(&j, r); err != nil {
		t.Fatal(err)
	}
	var roundtrip model.Report
	if err := json.Unmarshal(j.Bytes(), &roundtrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, roundtrip) {
		t.Fatal("JSON changed hostile source text")
	}
	if err := WriteMarkdown(&m, r); err != nil {
		t.Fatal(err)
	}
	// Every injected value is visibly represented in full, inside a code span
	// that cannot be closed by the payload or interpreted as an autolink.
	if got, want := strings.Count(m.String(), quote(payload)), 31; got != want {
		t.Fatalf("represented %d hostile values, want %d", got, want)
	}
	for _, forbidden := range []string{"<script", "</script", "`fence`", "\n# fake", "\x1b", "\x00", "\x07", "\u0085", "\u2028", "\u2029", "\u202E", "\u2066"} {
		if strings.Contains(m.String(), forbidden) {
			t.Fatalf("active/hidden content %q in Markdown", forbidden)
		}
	}
	for _, required := range []string{"not independently attested", "not independent evidence", "does not establish a fix", "this report is incomparable"} {
		if !strings.Contains(m.String(), required) {
			t.Fatalf("missing limitation %q", required)
		}
	}
}

func TestMarkdownDistinguishesUnicodeSpaces(t *testing.T) {
	r := load(t, "report-none")
	r.Baseline.Firmware.BuildID = "café batch 7"
	r.Candidate.Firmware.BuildID = "café\u00a0batch\u202f7"

	var md bytes.Buffer
	if err := WriteMarkdown(&md, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"`\"café batch 7\"`", "`\"café\\u{A0}batch\\u{202F}7\"`"} {
		if !strings.Contains(md.String(), "- firmware.build_id: "+want+"\n") {
			t.Errorf("missing Markdown build label %s", want)
		}
	}

	var j bytes.Buffer
	if err := WriteJSON(&j, r); err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal(j.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Candidate.Firmware.BuildID != r.Candidate.Firmware.BuildID {
		t.Errorf("JSON changed the build label to %q", decoded.Candidate.Firmware.BuildID)
	}
}

func TestAttributesAbsentAndPresentEmpty(t *testing.T) {
	r := load(t, "report-unchanged")
	r.Records = r.Records[3:4]
	r.Counts = model.Counts{ContextChanged: 1}
	row := &r.Records[0]
	row.Category = model.ContextChanged
	empty := ""
	row.After.Attributes = model.Attributes{Detail: &empty, Description: &empty, Summary: &empty, Link: &empty, Modified: &empty, ScoreV2: &empty, ScoreV3: &empty, ScoreV4: &empty, Vector: &empty, VectorString: &empty}
	row.ChangedFields = []string{"detail", "description", "summary", "link", "modified", "scorev2", "scorev3", "scorev4", "vector", "vectorString"}
	r.Decision = model.ChangesDetected
	var j, m bytes.Buffer
	if err := WriteJSON(&j, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&m, r); err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal(j.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, decoded) {
		t.Fatal("lost empty/absent attributes")
	}
	for _, a := range row.ChangedFields {
		if !strings.Contains(m.String(), "- "+a+": `\"\"`") {
			t.Fatalf("missing present empty %s", a)
		}
	}
	if !strings.Contains(m.String(), "Recognized attributes: none present") {
		t.Fatal("missing absent attributes")
	}
}

type brokenWriter struct {
	n   int
	err error
}

func (w brokenWriter) Write(p []byte) (int, error) { return min(w.n, len(p)), w.err }

func TestWriterFailures(t *testing.T) {
	sentinel := errors.New("writer failed")
	r := load(t, "report-changes")
	for _, f := range []func(io.Writer, model.Report) error{WriteJSON, WriteMarkdown} {
		for _, tc := range []struct {
			w    io.Writer
			want error
		}{
			{brokenWriter{0, sentinel}, sentinel}, {brokenWriter{20, sentinel}, sentinel},
			{brokenWriter{0, nil}, io.ErrShortWrite}, {brokenWriter{20, nil}, io.ErrShortWrite},
		} {
			if err := f(tc.w, r); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		}
		if err := f(nil, r); err == nil {
			t.Fatal("nil writer accepted")
		}
	}
}

func TestNoFindingRecords(t *testing.T) {
	r := load(t, "report-unchanged")
	r.Records = []model.Record{}
	r.Counts = model.Counts{}
	// A component with no findings may still change version; that alone does
	// not trigger a selected finding category.
	r.ComponentVersionChanges = []model.ComponentVersionChange{{Component: model.ComponentID{Layer: "meta", Name: "empty"}, Before: "1", After: "2"}}
	var j, m bytes.Buffer
	if err := WriteJSON(&j, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&m, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.String(), "No finding records") {
		t.Fatal("missing empty records explanation")
	}
}

func TestContradictoryAbsenceReasons(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		r := load(t, "report-changes")
		r.Records = []model.Record{r.Records[0], r.Records[3]}
		r.Records[1].Component = r.Records[0].Component
		r.Records[1].After.Version = r.Records[0].After.Version
		r.Counts = model.Counts{New: 2}
		r.ComponentVersionChanges = []model.ComponentVersionChange{}
		if reverse {
			slices.Reverse(r.Records)
		}
		for _, f := range []func(io.Writer, model.Report) error{WriteJSON, WriteMarkdown} {
			var b bytes.Buffer
			if err := f(&b, r); err == nil || b.Len() != 0 {
				t.Fatal("contradictory absence accepted")
			}
		}
	}
}

func FuzzQuotedMarkdown(f *testing.F) {
	f.Add("text\n[link](https://example.invalid)\x1b[31m\u202E")
	f.Add("&lt;img&gt; ` | \\ ")
	f.Fuzz(func(t *testing.T, s string) {
		got := quote(s)
		if !strings.HasPrefix(got, "`\"") || !strings.HasSuffix(got, "\"`") {
			t.Fatal("missing quoted code span")
		}
		for _, r := range got[1 : len(got)-1] {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '<' || r == '>' || r == '&' || r == '`' || r == '|' || r == '\u2028' || r == '\u2029' {
				t.Fatalf("unsafe rune %q", r)
			}
		}
	})
}
