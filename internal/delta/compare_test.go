// SPDX-License-Identifier: Apache-2.0

package delta_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/cvedelta/internal/delta"
	"github.com/firmdura/cvedelta/internal/model"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../testdata/provenance", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decode[T any](t *testing.T, data []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

// Trusted frozen fixtures are decoded directly to keep comparison tests
// independent of the reader package and its strict stream validation.
func fixtureInput(t *testing.T, report, metadata string) model.Input {
	t.Helper()
	raw := readFixture(t, report)
	hash := sha256.Sum256(raw)
	input, err := model.NewInput(decode[model.Document](t, raw), decode[model.Metadata](t, readFixture(t, metadata)), hex.EncodeToString(hash[:]))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func construct(t *testing.T, document model.Document, metadata model.Metadata) model.Input {
	t.Helper()
	input, err := model.NewInput(document, metadata, metadata.ReportSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func metadata() model.Metadata {
	return model.Metadata{
		SchemaVersion: model.SchemaVersion, ReportSHA256: strings.Repeat("a", 64),
		Firmware: model.Firmware{ConfigurationID: "test:machine:distro", BuildID: "test-build", SourceRevision: "test-source"},
		Scanner:  model.Scanner{Name: model.ScannerName, Revision: "test-producer"},
		Database: model.Database{SHA256: strings.Repeat("b", 64)},
		Coverage: model.Coverage{ScopeSHA256: strings.Repeat("c", 64), Complete: true},
	}
}

func document(components ...model.Component) model.Document {
	if components == nil {
		components = []model.Component{}
	}
	return model.Document{Version: model.ReportVersion, Components: components}
}

func component(layer, name, version string, issues ...model.Issue) model.Component {
	if issues == nil {
		issues = []model.Issue{}
	}
	return model.Component{Layer: layer, Name: name, Version: version, Issues: issues}
}

func issue(id string, status model.Status) model.Issue {
	return model.Issue{ID: id, Status: status}
}

func text(value string) *string { return &value }

func compare(t *testing.T, before, after model.Input) model.Delta {
	t.Helper()
	got, err := delta.Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestFrozenExpectedDeltas(t *testing.T) {
	for _, tc := range []struct {
		name, beforeReport, beforeMeta, afterReport, afterMeta, expected string
	}{
		{"all categories", "baseline.json", "baseline.meta.json", "candidate.json", "candidate.meta.json", "report-changes.json"},
		{"same report", "baseline.json", "baseline.meta.json", "baseline.json", "baseline.meta.json", "report-unchanged.json"},
		{"all provenance limitations", "baseline.json", "baseline-incomplete.meta.json", "candidate.json", "all-incomparable.meta.json", "report-incomparable.json"},
		{"unchanged with incomplete coverage", "baseline.json", "baseline-incomplete.meta.json", "baseline.json", "baseline.meta.json", "report-incomparable-unchanged.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := fixtureInput(t, "synthetic/"+tc.beforeReport, "synthetic/"+tc.beforeMeta)
			after := fixtureInput(t, "synthetic/"+tc.afterReport, "synthetic/"+tc.afterMeta)
			want := decode[model.Report](t, readFixture(t, "synthetic/"+tc.expected)).Delta
			got := compare(t, before, after)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("delta differs from frozen expected example\ngot:  %#v\nwant: %#v", got, want)
			}
			assertUnion(t, before, after, got)
		})
	}
}

func TestProducerFixtureSelfComparison(t *testing.T) {
	input := fixtureInput(t, "producer/report.json", "producer/report.meta.json")
	got := compare(t, input, input)
	assertUnion(t, input, input, got)
	if !got.Comparable || got.Counts.Unchanged != len(got.Records) || len(got.ComponentVersionChanges) != 0 {
		t.Fatalf("producer self comparison changed: %#v", got)
	}
}

func TestInvalidInputsAndConfigurationReturnNoDelta(t *testing.T) {
	valid := construct(t, document(), metadata())
	mismatch := metadata()
	mismatch.Firmware.ConfigurationID += " " // Identity is exact; no trimming.
	mismatch.Scanner.Revision = "another-producer"
	mismatch.Coverage.Complete = false
	otherConfiguration := construct(t, document(), mismatch)
	for _, tc := range []struct {
		name          string
		before, after model.Input
	}{
		{"both invalid", model.Input{}, model.Input{}},
		{"invalid baseline", model.Input{}, valid},
		{"invalid candidate", valid, model.Input{}},
		{"configuration mismatch beats provenance limitations", valid, otherConfiguration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := delta.Compare(tc.before, tc.after)
			if err == nil || !reflect.DeepEqual(got, model.Delta{}) {
				t.Fatalf("expected error with zero Delta; got %#v, %v", got, err)
			}
		})
	}
}

func TestProvenanceReasonsWithNoFindingChanges(t *testing.T) {
	all := []model.ReasonCode{model.ScannerRevisionChanged, model.DatabaseChanged, model.CoverageScopeChanged, model.BaselineCoverageIncomplete, model.CandidateCoverageIncomplete}
	for _, tc := range []struct {
		name   string
		mutate func(*model.Metadata, *model.Metadata)
		codes  []model.ReasonCode
	}{
		{"same metadata", func(_, _ *model.Metadata) {}, []model.ReasonCode{}},
		{"scanner revision", func(_, a *model.Metadata) { a.Scanner.Revision += "-changed" }, all[0:1]},
		{"database", func(_, a *model.Metadata) { a.Database.SHA256 = strings.Repeat("d", 64) }, all[1:2]},
		{"coverage scope", func(_, a *model.Metadata) { a.Coverage.ScopeSHA256 = strings.Repeat("e", 64) }, all[2:3]},
		{"baseline incomplete", func(b, _ *model.Metadata) { b.Coverage.Complete = false }, all[3:4]},
		{"candidate incomplete", func(_, a *model.Metadata) { a.Coverage.Complete = false }, all[4:5]},
		{"both incomplete", func(b, a *model.Metadata) { b.Coverage.Complete = false; a.Coverage.Complete = false }, all[3:5]},
		{"all limitations", func(b, a *model.Metadata) {
			a.Scanner.Revision += "-changed"
			a.Database.SHA256 = strings.Repeat("d", 64)
			a.Coverage.ScopeSHA256 = strings.Repeat("e", 64)
			b.Coverage.Complete, a.Coverage.Complete = false, false
		}, all},
		{"build identity allowed", func(_, a *model.Metadata) { a.Firmware.BuildID += "-changed" }, []model.ReasonCode{}},
		{"source revision allowed", func(_, a *model.Metadata) { a.Firmware.SourceRevision += "-changed" }, []model.ReasonCode{}},
		{"report hash allowed", func(_, a *model.Metadata) { a.ReportSHA256 = strings.Repeat("f", 64) }, []model.ReasonCode{}},
		{"all permitted differences", func(_, a *model.Metadata) {
			a.Firmware.BuildID += "-changed"
			a.Firmware.SourceRevision += "-changed"
			a.ReportSHA256 = strings.Repeat("f", 64)
		}, []model.ReasonCode{}},
	} {
		for _, populated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/populated=%v", tc.name, populated), func(t *testing.T) {
				b, a := metadata(), metadata()
				tc.mutate(&b, &a)
				doc := document()
				if populated {
					doc = document(component("meta", "same", "1", issue("CVE-2099-0001", model.Patched)))
				}
				before, after := construct(t, doc, b), construct(t, doc, a)
				got := compare(t, before, after)
				codes := make([]model.ReasonCode, 0, len(got.Reasons))
				for _, reason := range got.Reasons {
					codes = append(codes, reason.Code)
					if strings.TrimSpace(reason.Message) == "" {
						t.Fatal("reason has no explanatory message")
					}
				}
				if !reflect.DeepEqual(codes, tc.codes) || got.Comparable != (len(tc.codes) == 0) {
					t.Fatalf("got reasons %v, comparable %v; want %v", codes, got.Comparable, tc.codes)
				}
				if got.Baseline != b || got.Candidate != a || got.Counts.Unchanged != len(got.Records) {
					t.Fatal("lost metadata or reported changes from provenance alone")
				}
				assertUnion(t, before, after, got)
			})
		}
	}
}

func TestSourcePermutationsHaveIdenticalDeltas(t *testing.T) {
	before := fixtureInput(t, "synthetic/baseline.json", "synthetic/baseline.meta.json")
	after := fixtureInput(t, "synthetic/candidate.json", "synthetic/candidate.meta.json")
	want := compare(t, before, after)
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(12, 42))
	for attempt := 0; attempt < 50; attempt++ {
		shuffle := func(input model.Input) model.Input {
			doc := input.Document()
			rng.Shuffle(len(doc.Components), func(i, j int) { doc.Components[i], doc.Components[j] = doc.Components[j], doc.Components[i] })
			for _, c := range doc.Components {
				rng.Shuffle(len(c.Issues), func(i, j int) { c.Issues[i], c.Issues[j] = c.Issues[j], c.Issues[i] })
			}
			return construct(t, doc, input.Metadata())
		}
		b, a := shuffle(before), shuffle(after)
		got := compare(t, b, a)
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) || string(gotJSON) != string(wantJSON) {
			t.Fatalf("permutation %d changed output", attempt)
		}
		assertUnion(t, b, a, got)
	}
}

func TestComparisonDoesNotMutateOrAliasInputs(t *testing.T) {
	before := fixtureInput(t, "synthetic/baseline.json", "synthetic/baseline.meta.json")
	after := fixtureInput(t, "synthetic/candidate.json", "synthetic/candidate.meta.json")
	bDoc, aDoc := before.Document(), after.Document()
	want := compare(t, before, after)
	got := compare(t, before, after)
	for _, record := range got.Records {
		for _, context := range []*model.Context{record.Before, record.After} {
			if context != nil {
				context.Version = "mutated output"
				if context.Attributes.Detail != nil {
					*context.Attributes.Detail = "mutated output"
				}
			}
		}
	}
	if !reflect.DeepEqual(before.Document(), bDoc) || !reflect.DeepEqual(after.Document(), aDoc) || !reflect.DeepEqual(compare(t, before, after), want) {
		t.Fatal("comparison/result mutation changed immutable Inputs or later comparisons")
	}
	self := compare(t, before, before)
	*self.Records[0].Before.Attributes.Detail = "mutated before"
	if *self.Records[0].After.Attributes.Detail != "old reported reason" {
		t.Fatal("before and after contexts alias each other for self comparison")
	}
}

func assertUnion(t *testing.T, before, after model.Input, got model.Delta) {
	t.Helper()
	type identity struct{ layer, name, cve string }
	union := map[identity]bool{}
	for _, input := range []model.Input{before, after} {
		for _, c := range input.Document().Components {
			for _, i := range c.Issues {
				union[identity{c.Layer, c.Name, i.ID}] = true
			}
		}
	}
	seen := map[identity]bool{}
	counts := model.Counts{}
	for _, r := range got.Records {
		id := identity{r.Component.Layer, r.Component.Name, r.CVEID}
		if !union[id] || seen[id] {
			t.Fatalf("unexpected or duplicate union identity: %#v", id)
		}
		seen[id] = true
		if r.ChangedFields == nil {
			t.Fatal("changed_fields must be an array")
		}
		switch r.Category {
		case model.New:
			counts.New++
		case model.NoLongerReported:
			counts.NoLongerReported++
		case model.StatusChanged:
			counts.StatusChanged++
		case model.ContextChanged:
			counts.ContextChanged++
		case model.Unchanged:
			counts.Unchanged++
		default:
			t.Fatalf("unknown category %q", r.Category)
		}
	}
	if len(seen) != len(union) || counts != got.Counts {
		t.Fatalf("union/counts incomplete: %d of %d, counts %#v vs %#v", len(seen), len(union), got.Counts, counts)
	}
	if got.SchemaVersion != model.SchemaVersion || got.Records == nil || got.Reasons == nil || got.ComponentVersionChanges == nil {
		t.Fatal("missing schema version or array")
	}
}
