// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/cvedelta/internal/model"
)

const emptyReport = `{"version":"1","package":[]}`
const oneIssue = `{"id":"CVE-2024-1234","status":"Unpatched"}`

func component(name, version, issues string) string {
	return `{"name":` + name + `,"layer":"meta","version":` + version + `,"issue":[` + issues + `]}`
}

func report(components ...string) string {
	return `{"version":"1","package":[` + strings.Join(components, ",") + `]}`
}

func validMetadata(raw []byte) model.Metadata {
	h := sha256.Sum256(raw)
	return model.Metadata{
		SchemaVersion: model.SchemaVersion, ReportSHA256: hex.EncodeToString(h[:]),
		Firmware: model.Firmware{ConfigurationID: "fixture:target:image", BuildID: "fixture-build", SourceRevision: "fixture-source"},
		Scanner:  model.Scanner{Name: model.ScannerName, Revision: "fixture-producer"},
		Database: model.Database{SHA256: strings.Repeat("a", 64)},
		Coverage: model.Coverage{ScopeSHA256: strings.Repeat("b", 64), Complete: true},
	}
}

func metadata(t *testing.T, raw []byte) []byte {
	t.Helper()
	b, err := json.Marshal(validMetadata(raw))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertInvalid(t *testing.T, raw, meta []byte, path string) {
	t.Helper()
	input, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(meta))
	if err == nil || input.Valid() {
		t.Fatalf("expected invalid Input and error, got valid=%v, err=%v", input.Valid(), err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not identify %q", err, path)
	}
}

func TestReadInputFrozenFixtures(t *testing.T) {
	for _, name := range []string{"producer/report", "synthetic/baseline", "synthetic/candidate"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("../../testdata/provenance", name)
			raw, err := os.ReadFile(path + ".json")
			if err != nil {
				t.Fatal(err)
			}
			meta, err := os.ReadFile(path + ".meta.json")
			if err != nil {
				t.Fatal(err)
			}
			rawBefore, metaBefore := bytes.Clone(raw), bytes.Clone(meta)
			input, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(meta))
			if err != nil {
				t.Fatal(err)
			}
			var want model.Document
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			var wantMeta model.Metadata
			if err := json.Unmarshal(meta, &wantMeta); err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(raw)
			if !input.Valid() || !reflect.DeepEqual(input.Document(), want) || input.Metadata() != wantMeta || input.RawSHA256() != hex.EncodeToString(h[:]) {
				t.Fatal("reader changed the frozen fixture or lost its provenance")
			}
			if !bytes.Equal(raw, rawBefore) || !bytes.Equal(meta, metaBefore) {
				t.Fatal("reader mutated source bytes")
			}
			for path, before := range map[string][]byte{path + ".json": rawBefore, path + ".meta.json": metaBefore} {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("source file changed: %s (%v)", path, err)
				}
			}
			copy := input.Document()
			copy.Components[0].Version = "changed accessor"
			for _, pointer := range []*string{copy.Components[0].Issues[0].Detail, copy.Components[0].Issues[0].Summary} {
				if pointer != nil {
					*pointer = "changed pointer"
				}
			}
			if !reflect.DeepEqual(input.Document(), want) {
				t.Fatal("Input leaked mutable aliases")
			}
		})
	}
}

func TestReadInputValidShapesAndExactText(t *testing.T) {
	text := " reason \"quoted\"\nsecond line\t<&>|` \U0001f680"
	textJSON, _ := json.Marshal(text)
	attributes := `,"detail":` + string(textJSON) + `,"description":"","summary":"s","link":"javascript:opaque","modified":"not a date","scorev2":"0","scorev3":"not a score","scorev4":"","vector":"x","vectorString":"y"`
	issue := strings.TrimSuffix(oneIssue, "}") + attributes + `,"unknown":[null,true,42,{"nested":[{},[]]}]}`
	raw := []byte(" \n" + report(
		component(`" pkg-native "`, `" 1.0 "`, issue),
		component(`"lib32-pkg"`, `"2"`, `{"id":"CVE-0000-0000","status":"Patched"},{"id":"CVE-9999-12345","status":"Ignored"}`),
		component(`"pkg"`, `"1"`, ""),
	) + "\r\n\t")
	input, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(metadata(t, raw)))
	if err != nil {
		t.Fatal(err)
	}
	d := input.Document()
	got := d.Components[0].Issues[0]
	if d.Components[0].Name != " pkg-native " || d.Components[0].Version != " 1.0 " || *got.Detail != text || got.Description == nil || *got.Description != "" || *got.ScoreV3 != "not a score" {
		t.Fatal("source context was normalized or optional fields were lost")
	}
	if got.Modified == nil || got.VectorString == nil || d.Components[1].Issues[0].Detail != nil {
		t.Fatal("optional attributes lost their presence/absence")
	}
	for _, raw := range []string{emptyReport, report(component(`"empty"`, `"1"`, "")), `{"extra":{"x":1e999999999999999999},"version":"1","package":[],"products":null}`} {
		b := []byte(raw)
		m := validMetadata(b)
		m.Coverage.Complete = false
		meta, _ := json.Marshal(m)
		input, err := ReadInput(strings.NewReader(raw), bytes.NewReader(meta))
		if err != nil || !input.Valid() || input.Document().Components == nil || input.Metadata().Coverage.Complete {
			t.Fatalf("valid empty/extra/incomplete input failed: %v", err)
		}
	}
}

func TestReadInputReportRejections(t *testing.T) {
	good := report(component(`"pkg"`, `"1"`, oneIssue))
	cases := []struct{ name, raw, path string }{
		{"empty", "", "report"},
		{"not object", `[]`, "report"},
		{"null object", `null`, "report"},
		{"truncated", `{"version":"1","package":[`, "report.package"},
		{"trailing object", emptyReport + `{}`, "report"},
		{"trailing malformed", emptyReport + `garbage`, "report"},
		{"trailing null", emptyReport + ` null`, "report"},
		{"missing version", `{"package":[]}`, "report.version"},
		{"case sensitive version", `{"Version":"1","package":[]}`, "report.version"},
		{"numeric version", `{"version":1,"package":[]}`, "report.version"},
		{"null version", `{"version":null,"package":[]}`, "report.version"},
		{"unsupported version", `{"version":"2","package":[]}`, "report.version"},
		{"missing package", `{"version":"1"}`, "report.package"},
		{"null package", `{"version":"1","package":null}`, "report.package"},
		{"object package", `{"version":"1","package":{}}`, "report.package"},
		{"null component", report(`null`), "report.package[0]"},
		{"array component", report(`[]`), "report.package[0]"},
		{"duplicate component", report(component(`"pkg"`, `"1"`, ""), component(`"pkg"`, `"1"`, "")), "report.package[1]"},
		{"multiple versions", report(component(`"pkg"`, `"1"`, ""), component(`"pkg"`, `"2"`, "")), "report.package[1]"},
		{"duplicate row", report(component(`"pkg"`, `"1"`, oneIssue+","+oneIssue)), "report.package[0].issue[1]"},
		{"conflicting row", report(component(`"pkg"`, `"1"`, oneIssue+","+strings.ReplaceAll(oneIssue, "Unpatched", "Patched"))), "report.package[0].issue[1]"},
		{"null row", report(component(`"pkg"`, `"1"`, "null")), "report.package[0].issue[0]"},
		{"duplicate root key", `{"version":"1","package":[],"version":"1"}`, "report"},
		{"escaped duplicate key", strings.Replace(good, `"id":`, `"\u0069d":"CVE-2024-9999","id":`, 1), "report.package[0].issue[0]"},
		{"ignored root duplicate", strings.TrimSuffix(emptyReport, "}") + `,"products":{"x":1,"x":2}}`, "report.<metadata>"},
		{"ignored component duplicate", report(strings.TrimSuffix(component(`"pkg"`, `"1"`, ""), "}") + `,"products":[{"x":[{"same":0,"\u0073ame":1}]}]}`), "report.package[0].<metadata>"},
		{"ignored issue duplicate", strings.Replace(good, `"status":`, `"extra":{"x":1,"x":1},"status":`, 1), "report.package[0].issue[0].<metadata>"},
		{"bad ignored syntax", strings.TrimSuffix(emptyReport, "}") + `,"products":[1,]}`, "report.<metadata>"},
	}
	for _, key := range []string{"name", "layer", "version", "issue"} {
		var c map[string]json.RawMessage
		_ = json.Unmarshal([]byte(component(`"pkg"`, `"1"`, oneIssue)), &c)
		delete(c, key)
		b, _ := json.Marshal(c)
		cases = append(cases, struct{ name, raw, path string }{"missing " + key, report(string(b)), "report.package[0]." + key})
		for _, wrong := range []string{"null", "true", "42", `{}`} {
			c[key] = json.RawMessage(wrong)
			b, _ := json.Marshal(c)
			cases = append(cases, struct{ name, raw, path string }{key + " type " + wrong, report(string(b)), "report.package[0]." + key})
		}
		if key != "issue" {
			c[key] = json.RawMessage(`" \t\n"`)
			b, _ := json.Marshal(c)
			cases = append(cases, struct{ name, raw, path string }{key + " blank", report(string(b)), "report.package[0]"})
		}
	}
	for _, key := range []string{"id", "status", "detail", "description", "summary", "link", "modified", "scorev2", "scorev3", "scorev4", "vector", "vectorString"} {
		for _, wrong := range []string{"null", "3.1", "false", "[]", "{}"} {
			issue := strings.TrimSuffix(oneIssue, "}")
			if key == "id" || key == "status" {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal([]byte(oneIssue), &fields)
				fields[key] = json.RawMessage(wrong)
				b, _ := json.Marshal(fields)
				issue = string(b)
			} else {
				issue += `,"` + key + `":` + wrong + `}`
			}
			cases = append(cases, struct{ name, raw, path string }{key + " type " + wrong, report(component(`"pkg"`, `"1"`, issue)), "report.package[0].issue[0]." + key})
		}
	}
	for _, id := range []string{"cve-2024-1234", "CVE-2024-123", "CVE-24-1234", " CVE-2024-1234", "CVE-2024-1234\n", "CVE-202A-1234"} {
		idJSON, _ := json.Marshal(id)
		issue := `{"id":` + string(idJSON) + `,"status":"Patched"}`
		cases = append(cases, struct{ name, raw, path string }{"bad id " + id, report(component(`"pkg"`, `"1"`, issue)), "report.package[0].issue[0].id"})
	}
	for _, status := range []string{"Fixed", "patched", "Unpatched ", "", "Unknown"} {
		cases = append(cases, struct{ name, raw, path string }{"bad status " + status, strings.Replace(good, "Unpatched", status, 1), "report.package[0].issue[0].status"})
	}
	for _, key := range []string{"id", "status"} {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal([]byte(oneIssue), &fields)
		delete(fields, key)
		b, _ := json.Marshal(fields)
		cases = append(cases, struct{ name, raw, path string }{"missing " + key, report(component(`"pkg"`, `"1"`, string(b))), "report.package[0].issue[0]." + key})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.raw)
			assertInvalid(t, raw, metadata(t, raw), tc.path)
		})
	}
}

func TestReadInputTrailingJSONErrors(t *testing.T) {
	for _, stream := range []string{"report", "metadata"} {
		for _, tc := range []struct {
			name, suffix  string
			invalid       bool
			syntax        bool
			unexpectedEOF bool
		}{
			{"malformed suffix", " \n@" + strings.Repeat("PRIVATE-SUFFIX", 1000), true, true, false},
			{"incomplete literal", ` tru`, true, false, true},
			{"incomplete number", ` 1e`, true, false, true},
			{"incomplete string", ` "` + strings.Repeat("PRIVATE-SUFFIX", 1000), true, false, true},
			{"second object", `{}`, true, false, false},
			{"second scalar", ` null`, true, false, false},
			{"second string", ` "PRIVATE-SUFFIX"`, true, false, false},
			{"whitespace only", " \r\n\t", false, false, false},
		} {
			t.Run(stream+"/"+tc.name, func(t *testing.T) {
				raw := []byte(emptyReport)
				if stream == "report" {
					raw = append(raw, tc.suffix...)
				}
				meta := metadata(t, raw)
				if stream == "metadata" {
					meta = append(meta, tc.suffix...)
				}
				input, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(meta))
				if !tc.invalid {
					if err != nil || !input.Valid() {
						t.Fatalf("trailing whitespace rejected: %v", err)
					}
					return
				}
				if err == nil || input.Valid() || !strings.HasPrefix(err.Error(), stream+":") {
					t.Fatalf("invalid suffix lost rejection/location: valid=%v, err=%v", input.Valid(), err)
				}
				var syntax *json.SyntaxError
				if errors.As(err, &syntax) != tc.syntax {
					t.Fatalf("JSON syntax error type lost or fabricated: %v", err)
				}
				if errors.Is(err, io.ErrUnexpectedEOF) != tc.unexpectedEOF {
					t.Fatalf("incomplete JSON error identity lost or fabricated: %v", err)
				}
				if strings.Contains(err.Error(), "PRIVATE-SUFFIX") || strings.Contains(err.Error(), "%!") || len(err.Error()) > 512 {
					t.Fatalf("unsafe or malformed diagnostic: %v", err)
				}
			})
		}
	}
}

func TestReadInputMetadataRejections(t *testing.T) {
	raw := []byte(emptyReport)
	base := metadata(t, raw)
	paths := [][]string{{"schema_version"}, {"report_sha256"}, {"firmware"}, {"scanner"}, {"database"}, {"coverage"},
		{"firmware", "configuration_id"}, {"firmware", "build_id"}, {"firmware", "source_revision"},
		{"scanner", "name"}, {"scanner", "revision"}, {"database", "sha256"}, {"coverage", "scope_sha256"}, {"coverage", "complete"}}
	for _, path := range paths {
		for _, value := range []string{"missing", "null", `[]`, `42`, `true`, `""`} {
			t.Run(strings.Join(path, ".")+"/"+value, func(t *testing.T) {
				var m map[string]any
				_ = json.Unmarshal(base, &m)
				parent := m
				for _, key := range path[:len(path)-1] {
					parent = parent[key].(map[string]any)
				}
				key := path[len(path)-1]
				if value == "missing" {
					delete(parent, key)
				} else {
					parent[key] = json.RawMessage(value)
				}
				// complete:true is a valid boolean, and schema_version has a
				// separate exact numeric-equivalence table below.
				if key == "complete" && value == "true" {
					return
				}
				meta, _ := json.Marshal(m)
				where := "metadata." + strings.Join(path, ".")
				if value == `""` && len(path) == 2 && (path[0] == "firmware" || path[0] == "scanner") {
					where = "metadata." + path[0] // Shared model diagnoses these opaque identities together.
				}
				assertInvalid(t, raw, meta, where)
			})
		}
	}
	for _, parent := range []string{"", "firmware", "scanner", "database", "coverage"} {
		t.Run("extra "+parent, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(base, &m)
			object := m
			if parent != "" {
				object = m[parent].(map[string]any)
			}
			object["extra"] = nil
			meta, _ := json.Marshal(m)
			assertInvalid(t, raw, meta, "metadata")
		})
	}
	for _, tc := range []struct{ old, replacement, path string }{
		{`"schema_version":1`, `"Schema_version":1`, "metadata"},
		{`"schema_version":1`, `"schema_version":1,"schema_version":1`, "metadata"},
		{`"complete":true`, `"complete":false,"complete":true`, "metadata.coverage"},
		{`"revision":"fixture-producer"`, `"revision":"a","\u0072evision":"b"`, "metadata.scanner"},
		{strings.Repeat("a", 64), strings.Repeat("A", 64), "metadata.database.sha256"},
		{strings.Repeat("b", 64), "short", "metadata.coverage.scope_sha256"},
		{"yocto-cve-check", "other-scanner", "metadata.scanner"},
		{"fixture:target:image", " ", "metadata.firmware"},
		{"fixture-producer", " ", "metadata.scanner"},
	} {
		assertInvalid(t, raw, []byte(strings.Replace(string(base), tc.old, tc.replacement, 1)), tc.path)
	}
	for _, meta := range []string{"", "null", "[]", string(base) + "{}", string(base) + "!", strings.TrimSuffix(string(base), "}")} {
		assertInvalid(t, raw, []byte(meta), "metadata")
	}
}

func TestReadInputSchemaVersionExactNumbers(t *testing.T) {
	raw := []byte(emptyReport)
	base := string(metadata(t, raw))
	for _, number := range []string{"1", "1.0", "1e0", "0.1e1", "1000e-3", "10.00e-1", "1E+0000", "1e" + strings.Repeat("0", 1000)} {
		meta := strings.Replace(base, `"schema_version":1`, `"schema_version":`+number, 1)
		input, err := ReadInput(bytes.NewReader(raw), strings.NewReader(meta))
		if err != nil || input.Metadata().SchemaVersion != 1 {
			t.Fatalf("exact version %s rejected: %v", number, err)
		}
	}
	for _, number := range []string{"0", "2", "-1", "1.0000000000000001", "0.9999999999999999999999", "1e-1000000", "1e99999999999999999999", "1000e-2", "0.1e0", "1e-9223372036854775808"} {
		meta := strings.Replace(base, `"schema_version":1`, `"schema_version":`+number, 1)
		assertInvalid(t, raw, []byte(meta), "metadata.schema_version")
	}
}

func TestReadInputRawChecksum(t *testing.T) {
	raw := []byte(emptyReport)
	base := metadata(t, raw)
	assertInvalid(t, append(bytes.Clone(raw), '\n'), base, "metadata.report_sha256")
	assertInvalid(t, append([]byte(" "), raw...), base, "metadata.report_sha256")
	assertInvalid(t, raw, bytes.Replace(base, []byte(validMetadata(raw).ReportSHA256), []byte(strings.Repeat("0", 64)), 1), "metadata.report_sha256")
	assertInvalid(t, raw, bytes.Replace(base, []byte(validMetadata(raw).ReportSHA256), []byte(strings.ToUpper(validMetadata(raw).ReportSHA256)), 1), "metadata.report_sha256")
}

func TestReadInputUnicodeAndSafeDiagnostics(t *testing.T) {
	for _, escaped := range []string{`\ud800`, `\udc00`, `\ud800\u0000`, `\ud800x`, `\ud800\ud800`} {
		raw := []byte(strings.TrimSuffix(emptyReport, "}") + `,"unknown":"` + escaped + `"}`)
		assertInvalid(t, raw, metadata(t, raw), "report")
	}
	for _, escaped := range []string{`\ud83d\ude80`, `\\ud800`, `\ufffd`} {
		raw := []byte(strings.TrimSuffix(emptyReport, "}") + `,"unknown":"` + escaped + `"}`)
		if _, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(metadata(t, raw))); err != nil {
			t.Fatalf("valid Unicode %s rejected: %v", escaped, err)
		}
	}
	raw := append([]byte(strings.TrimSuffix(emptyReport, "}")+`,"unknown":"`), 0xff, '"', '}')
	assertInvalid(t, raw, metadata(t, raw), "report")
	good := []byte(emptyReport)
	meta := bytes.Replace(metadata(t, good), []byte("fixture-build"), []byte{0xff}, 1)
	assertInvalid(t, good, meta, "metadata")
	meta = bytes.Replace(metadata(t, good), []byte("fixture-build"), []byte(`\ud800`), 1)
	assertInvalid(t, good, meta, "metadata")
	secret := strings.Repeat("PRIVATE-REPORT-BODY", 1000)
	raw = []byte(strings.TrimSuffix(emptyReport, "}") + `,"` + secret + `":{"x":1,"x":2}}`)
	_, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(metadata(t, raw)))
	if err == nil || strings.Contains(err.Error(), "PRIVATE-REPORT-BODY") || len(err.Error()) > 200 {
		t.Fatalf("unsafe diagnostic: %v", err)
	}
}

func TestReadInputDeepIgnoredMetadata(t *testing.T) {
	// Walk deeply nested metadata without recursive calls in our parser.
	const depth = 1000
	for _, value := range []string{
		strings.Repeat("[", depth) + `{"x":1}` + strings.Repeat("]", depth),
		strings.Repeat(`{"nested":`, depth) + `true` + strings.Repeat("}", depth),
	} {
		raw := []byte(strings.TrimSuffix(emptyReport, "}") + `,"ignored":` + value + `}`)
		if _, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(metadata(t, raw))); err != nil {
			t.Fatalf("valid deeply nested metadata rejected: %v", err)
		}
	}
	value := strings.Repeat("[", depth) + `{"x":1,"x":2}` + strings.Repeat("]", depth)
	raw := []byte(strings.TrimSuffix(emptyReport, "}") + `,"ignored":` + value + `}`)
	assertInvalid(t, raw, metadata(t, raw), "report.<metadata>: duplicate")
	// JSON depth counts every open object/array, including the root report.
	for _, where := range []string{"root", "issue"} {
		baseDepth := 1
		if where == "issue" {
			baseDepth = 5 // report, package array, component, issue array, issue
		}
		for _, total := range []int{10000, 10001} {
			value := strings.Repeat("[", total-baseDepth) + `0` + strings.Repeat("]", total-baseDepth)
			if where == "root" {
				raw = []byte(strings.TrimSuffix(emptyReport, "}") + `,"ignored":` + value + `}`)
			} else {
				issue := strings.TrimSuffix(oneIssue, "}") + `,"ignored":` + value + `}`
				raw = []byte(report(component(`"pkg"`, `"1"`, issue)))
			}
			if total == 10001 {
				assertInvalid(t, raw, metadata(t, raw), "report")
			} else if _, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(metadata(t, raw))); err != nil {
				t.Fatalf("%s metadata at total depth %d rejected: %v", where, total, err)
			}
		}
	}
}

type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(b []byte) (int, error) {
	n := copy(b, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestReadInputIOErrors(t *testing.T) {
	sentinel := errors.New("fixture read failure")
	raw := []byte(emptyReport)
	meta := metadata(t, raw)
	for _, alongside := range []bool{false, true} {
		for _, failReport := range []bool{false, true} {
			var reportStream, metaStream io.Reader = bytes.NewReader(raw), bytes.NewReader(meta)
			var prefix []byte
			if alongside {
				prefix = raw
				if !failReport {
					prefix = meta
				}
			}
			failing := &failingReader{data: prefix, err: sentinel}
			if failReport {
				reportStream = failing
			} else {
				metaStream = failing
			}
			input, err := ReadInput(reportStream, metaStream)
			if input.Valid() || !errors.Is(err, sentinel) {
				t.Fatalf("I/O error not propagated: %v", err)
			}
		}
	}
	// A reader error after valid JSON and whitespace is still an input error.
	stream := io.MultiReader(bytes.NewReader(append(bytes.Clone(raw), ' ')), &failingReader{err: sentinel})
	if _, err := ReadInput(stream, bytes.NewReader(meta)); !errors.Is(err, sentinel) {
		t.Fatalf("post-document I/O error lost: %v", err)
	}
	for _, streams := range [][2]io.Reader{{nil, bytes.NewReader(meta)}, {bytes.NewReader(raw), nil}} {
		if input, err := ReadInput(streams[0], streams[1]); err == nil || input.Valid() {
			t.Fatal("nil reader accepted")
		}
	}
}

type repeatedByteReader struct {
	remaining int64
	read      int64
}

func (r *repeatedByteReader) Read(b []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(b)), r.remaining)
	for i := range b[:n] {
		b[i] = ' '
	}
	r.remaining -= n
	r.read += n
	return int(n), nil
}

func TestReadInputByteLimits(t *testing.T) {
	// Both exact limits are valid: padding is JSON whitespace and report bytes
	// are hashed in full. No large source fixture needs to be stored on disk.
	raw := make([]byte, model.MaxReportBytes)
	copy(raw, emptyReport)
	for i := len(emptyReport); i < len(raw); i++ {
		raw[i] = ' '
	}
	meta := metadata(t, raw)
	meta = append(meta, bytes.Repeat([]byte(" "), int(model.MaxMetadataBytes)-len(meta))...)
	if input, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(meta)); err != nil || !input.Valid() {
		t.Fatalf("exact byte limits rejected: %v", err)
	}
	for _, tc := range []struct {
		name  string
		limit int64
	}{{"report", model.MaxReportBytes}, {"metadata", model.MaxMetadataBytes}} {
		t.Run(tc.name, func(t *testing.T) {
			r := &repeatedByteReader{remaining: tc.limit + 4096}
			var reportStream, metaStream io.Reader = strings.NewReader(emptyReport), r
			if tc.name == "report" {
				reportStream, metaStream = r, bytes.NewReader(metadata(t, []byte(emptyReport)))
			}
			input, err := ReadInput(reportStream, metaStream)
			if input.Valid() || err == nil || !strings.Contains(err.Error(), tc.name+": byte limit") || r.read != tc.limit+1 {
				t.Fatalf("wrong overflow behavior: read=%d, err=%v", r.read, err)
			}
		})
	}
}

func TestReadInputComponentLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":"1","package":[`)
	for i := 0; i < model.MaxComponents; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"p%d","layer":"m","version":"1","issue":[]}`, i)
	}
	prefix := b.String()
	raw := []byte(prefix + `]}`)
	input, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(metadata(t, raw)))
	if err != nil || !input.Valid() || len(input.Document().Components) != model.MaxComponents {
		t.Fatalf("exact component count rejected: %v", err)
	}
	raw = []byte(prefix + `,` + component(`"extra"`, `"1"`, "") + `]}`)
	assertInvalid(t, raw, metadata(t, raw), "report.package: count limit")
}

func TestReadInputFindingLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":"1","package":[{"name":"p","layer":"m","version":"1","issue":[`)
	for i := 0; i < model.MaxFindings; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"CVE-0000-%04d","status":"Patched"}`, i)
	}
	prefix := b.String()
	raw := []byte(prefix + `]}]}`)
	input, err := ReadInput(bytes.NewReader(raw), bytes.NewReader(metadata(t, raw)))
	if err != nil || !input.Valid() {
		t.Fatalf("exact finding count rejected: %v", err)
	}
	// The excess row is in a different component, proving the limit is global.
	raw = []byte(prefix + `]},` + component(`"other"`, `"1"`, oneIssue) + `]}`)
	assertInvalid(t, raw, metadata(t, raw), "report.package[1].issue[0]: finding limit")
}
