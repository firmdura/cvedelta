// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/cvedelta/internal/model"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../..", path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func fixture(t *testing.T) (model.Document, model.Metadata, string) {
	t.Helper()
	b := read(t, "testdata/provenance/synthetic/baseline.json")
	h := sha256.Sum256(b)
	return decode[model.Document](t, b), decode[model.Metadata](t, read(t, "testdata/provenance/synthetic/baseline.meta.json")), hex.EncodeToString(h[:])
}
func TestContractImmutableInput(t *testing.T) {
	d, m, h := fixture(t)
	input, err := model.NewInput(d, m, h)
	if err != nil {
		t.Fatal(err)
	}
	*d.Components[0].Issues[0].Detail = "mutated source"
	d.Components[0].Version = "mutated version"
	got := input.Document()
	if *got.Components[0].Issues[0].Detail != "old reported reason" || got.Components[0].Version != "1.0" {
		t.Fatal("constructor retained mutable aliases")
	}
	*got.Components[0].Issues[0].Detail = "mutated accessor"
	got.Components[0].Issues = nil
	if *input.Document().Components[0].Issues[0].Detail != "old reported reason" {
		t.Fatal("accessor retained mutable aliases")
	}
	if !input.Valid() || input.RawSHA256() != h || input.Metadata() != m {
		t.Fatal("input lost validation/provenance")
	}
	if (model.Input{}).Valid() {
		t.Fatal("zero Input is valid")
	}
}
func TestContractSemanticRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Document, *model.Metadata, *string)
	}{
		{"unsupported version", func(d *model.Document, _ *model.Metadata, _ *string) { d.Version = "2" }},
		{"missing package", func(d *model.Document, _ *model.Metadata, _ *string) { d.Components = nil }},
		{"missing issue", func(d *model.Document, _ *model.Metadata, _ *string) { d.Components[0].Issues = nil }},
		{"blank component", func(d *model.Document, _ *model.Metadata, _ *string) { d.Components[0].Name = " \t" }},
		{"duplicate component even another version", func(d *model.Document, _ *model.Metadata, _ *string) {
			c := d.Components[0]
			c.Version = "different"
			d.Components = append(d.Components, c)
		}},
		{"duplicate row", func(d *model.Document, _ *model.Metadata, _ *string) {
			d.Components[0].Issues = append(d.Components[0].Issues, d.Components[0].Issues[0])
		}},
		{"lowercase CVE", func(d *model.Document, _ *model.Metadata, _ *string) { d.Components[0].Issues[0].ID = "cve-2024-1234" }},
		{"short CVE", func(d *model.Document, _ *model.Metadata, _ *string) { d.Components[0].Issues[0].ID = "CVE-2024-123" }},
		{"unknown status", func(d *model.Document, _ *model.Metadata, _ *string) { d.Components[0].Issues[0].Status = "Fixed" }},
		{"metadata version", func(_ *model.Document, m *model.Metadata, _ *string) { m.SchemaVersion = 2 }},
		{"checksum mismatch", func(_ *model.Document, m *model.Metadata, _ *string) { m.ReportSHA256 = strings.Repeat("0", 64) }},
		{"raw hash syntax", func(_ *model.Document, _ *model.Metadata, h *string) { *h = "bad" }},
		{"blank configuration", func(_ *model.Document, m *model.Metadata, _ *string) { m.Firmware.ConfigurationID = " " }},
		{"missing build", func(_ *model.Document, m *model.Metadata, _ *string) { m.Firmware.BuildID = "" }},
		{"missing source", func(_ *model.Document, m *model.Metadata, _ *string) { m.Firmware.SourceRevision = "" }},
		{"scanner name", func(_ *model.Document, m *model.Metadata, _ *string) { m.Scanner.Name = "other" }},
		{"missing scanner revision", func(_ *model.Document, m *model.Metadata, _ *string) { m.Scanner.Revision = "" }},
		{"uppercase database hash", func(_ *model.Document, m *model.Metadata, _ *string) { m.Database.SHA256 = strings.Repeat("A", 64) }},
		{"coverage hash", func(_ *model.Document, m *model.Metadata, _ *string) { m.Coverage.ScopeSHA256 = "bad" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, m, h := fixture(t)
			tc.mutate(&d, &m, &h)
			if _, err := model.NewInput(d, m, h); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	d, m, h := fixture(t)
	m.Coverage.Complete = false
	d.Components = []model.Component{}
	if _, err := model.NewInput(d, m, h); err != nil {
		t.Fatalf("empty report/incomplete provenance is valid input: %v", err)
	}
}
func schemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.LoadURL = func(url string) (io.ReadCloser, error) {
		return nil, fmt.Errorf("external schema load prohibited: %s", url)
	}
	names := []string{"yocto-v1", "metadata-v1", "report-v1"}
	for _, n := range names {
		if err := c.AddResource("file:///schemas/"+n+".schema.json", bytes.NewReader(read(t, "schemas/"+n+".schema.json"))); err != nil {
			t.Fatal(err)
		}
	}
	out := map[string]*jsonschema.Schema{}
	for _, n := range names {
		s, err := c.Compile("file:///schemas/" + n + ".schema.json")
		if err != nil {
			t.Fatal(err)
		}
		out[n] = s
	}
	return out
}
func TestContractSchemasAndFixtures(t *testing.T) {
	ss := schemas(t)
	for _, name := range []string{"synthetic/baseline.json", "synthetic/candidate.json", "producer/report.json"} {
		t.Run(name, func(t *testing.T) {
			b := read(t, "testdata/provenance/"+name)
			if err := ss["yocto-v1"].Validate(decode[any](t, b)); err != nil {
				t.Fatal(err)
			}
			metaPath := strings.TrimSuffix(name, ".json") + ".meta.json"
			m := decode[model.Metadata](t, read(t, "testdata/provenance/"+metaPath))
			h := sha256.Sum256(b)
			if _, err := model.NewInput(decode[model.Document](t, b), m, hex.EncodeToString(h[:])); err != nil {
				t.Fatal(err)
			}
		})
	}
	paths, err := filepath.Glob("../../testdata/provenance/*/*.meta.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := ss["metadata-v1"].Validate(decode[any](t, b)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"report-changes.json", "report-none.json", "report-incomparable.json", "report-unchanged.json", "report-incomparable-unchanged.json"} {
		t.Run(name, func(t *testing.T) {
			b := read(t, "testdata/provenance/synthetic/"+name)
			if err := ss["report-v1"].Validate(decode[any](t, b)); err != nil {
				t.Fatal(err)
			}
			r := decode[model.Report](t, b)
			out, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decode[any](t, b), decode[any](t, out)) {
				t.Fatal("report JSON lost source fields, null/empty distinctions or text")
			}
		})
	}
}
func TestContractSchemaRejections(t *testing.T) {
	ss := schemas(t)
	cases := []struct {
		name, schema, file string
		mutate             func(map[string]any)
	}{
		{"missing complete", "metadata-v1", "baseline.meta.json", func(v map[string]any) { delete(v["coverage"].(map[string]any), "complete") }},
		{"unknown nested envelope", "metadata-v1", "baseline.meta.json", func(v map[string]any) { v["scanner"].(map[string]any)["extra"] = true }},
		{"unknown envelope", "metadata-v1", "baseline.meta.json", func(v map[string]any) { v["extra"] = true }},
		{"null known attribute", "yocto-v1", "baseline.json", func(v map[string]any) {
			v["package"].([]any)[0].(map[string]any)["issue"].([]any)[0].(map[string]any)["summary"] = nil
		}},
		{"numeric score", "yocto-v1", "baseline.json", func(v map[string]any) {
			v["package"].([]any)[0].(map[string]any)["issue"].([]any)[0].(map[string]any)["scorev3"] = 7.5
		}},
		{"incomparable clean", "report-v1", "report-incomparable.json", func(v map[string]any) { v["decision"] = "clean" }},
		{"new has before", "report-v1", "report-changes.json", func(v map[string]any) {
			v["records"].([]any)[0].(map[string]any)["before"] = v["records"].([]any)[0].(map[string]any)["after"]
		}},
		{"unchanged gating", "report-v1", "report-changes.json", func(v map[string]any) { v["policy"].(map[string]any)["fail_on"] = []any{"unchanged"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := decode[map[string]any](t, read(t, "testdata/provenance/synthetic/"+tc.file))
			tc.mutate(v)
			if err := ss[tc.schema].Validate(v); err == nil {
				t.Fatal("invalid schema example accepted")
			}
		})
	}
}
func TestContractOutcomesAndIdentity(t *testing.T) {
	var matrix struct {
		Cases []struct {
			Name         string
			ExpectedExit int `json:"expected_exit"`
			Report       *string
		} `json:"cases"`
	}
	matrix = decode[struct {
		Cases []struct {
			Name         string
			ExpectedExit int `json:"expected_exit"`
			Report       *string
		} `json:"cases"`
	}](t, read(t, "testdata/provenance/synthetic/outcomes.json"))
	mapping := map[model.Decision]int{model.Clean: model.ExitClean, model.ChangesDetected: model.ExitChangesDetected, model.Incomparable: model.ExitIncomparable}
	for _, tc := range matrix.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Report == nil {
				if tc.ExpectedExit != model.ExitError {
					t.Fatal("invalid input must exit 2 without report")
				}
				return
			}
			r := decode[model.Report](t, read(t, "testdata/provenance/synthetic/"+*tc.Report))
			if mapping[r.Decision] != tc.ExpectedExit {
				t.Fatal("decision/exit contract mismatch")
			}
		})
	}
	r := decode[model.Report](t, read(t, "testdata/provenance/synthetic/report-changes.json"))
	if len(r.Records) != 10 || r.Counts != (model.Counts{New: 2, NoLongerReported: 2, StatusChanged: 1, ContextChanged: 2, Unchanged: 3}) {
		t.Fatal("fixture must account for each union identity")
	}
	status := r.Records[1]
	if status.Category != model.StatusChanged || !reflect.DeepEqual(status.ChangedFields, []string{"version", "status", "detail"}) || status.Before.Version == status.After.Version {
		t.Fatal("version is context and status change retains all context changes")
	}
	if r.Records[5].Component.Name != "alpha-native" || r.Records[7].Component.Name != "lib32-alpha" {
		t.Fatal("native/multilib identities merged")
	}
}
