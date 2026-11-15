// SPDX-License-Identifier: Apache-2.0

package decision_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/firmdura/cvedelta/internal/decision"
	"github.com/firmdura/cvedelta/internal/delta"
	"github.com/firmdura/cvedelta/internal/model"
)

var categories = []model.Category{
	model.New, model.NoLongerReported, model.StatusChanged, model.ContextChanged,
}

func readJSON[T any](t *testing.T, path string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../..", path))
	if err != nil {
		t.Fatal(err)
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
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

func document(version string, issues ...model.Issue) model.Document {
	if issues == nil {
		issues = []model.Issue{}
	}
	return model.Document{Version: model.ReportVersion, Components: []model.Component{{
		Layer: "test-layer", Name: "test-component", Version: version, Issues: issues,
	}}}
}

func input(t *testing.T, doc model.Document, meta model.Metadata) model.Input {
	t.Helper()
	value, err := model.NewInput(doc, meta, meta.ReportSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func compare(t *testing.T, before, after model.Document, beforeMeta, afterMeta model.Metadata) model.Delta {
	t.Helper()
	value, err := delta.Compare(input(t, before, beforeMeta), input(t, after, afterMeta))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func oneCategory(t *testing.T, category model.Category) model.Delta {
	t.Helper()
	issue := model.Issue{ID: "CVE-2026-1234", Status: model.Unpatched}
	before, after := document("1", issue), document("1", issue)
	switch category {
	case model.New:
		before = document("1")
	case model.NoLongerReported:
		after = document("1")
	case model.StatusChanged:
		after.Components[0].Issues[0].Status = model.Patched
	case model.ContextChanged:
		after.Components[0].Version = "2"
	case model.Unchanged:
	case "empty":
		before, after = document("1"), document("1")
	case "version_only":
		before, after = document("1"), document("2")
	default:
		t.Fatalf("unknown test category %q", category)
	}
	return compare(t, before, after, metadata(), metadata())
}

func TestApplyEveryPolicySubset(t *testing.T) {
	// Every changed category must be independently gateable, while unchanged and
	// version changes without findings never trigger policy by themselves.
	for _, category := range append(slices.Clone(categories), model.Unchanged, "empty", "version_only") {
		observed := oneCategory(t, category)
		for mask := range 16 {
			t.Run(fmt.Sprintf("%s/subset_%04b", category, mask), func(t *testing.T) {
				selection := []model.Category{}
				// Reverse the request order to exercise policy canonicalization.
				for i := len(categories) - 1; i >= 0; i-- {
					if mask&(1<<i) != 0 {
						selection = append(selection, categories[i])
					}
				}
				originalSelection := slices.Clone(selection)
				got, err := decision.Apply(observed, model.Options{FailOn: selection})
				if err != nil {
					t.Fatal(err)
				}
				want := model.Clean
				if slices.Contains(selection, category) {
					want = model.ChangesDetected
				}
				if got.Decision != want {
					t.Fatalf("decision = %q, want %q", got.Decision, want)
				}
				wantPolicy := []model.Category{}
				for _, c := range categories {
					if slices.Contains(selection, c) {
						wantPolicy = append(wantPolicy, c)
					}
				}
				if !reflect.DeepEqual(got.Policy.FailOn, wantPolicy) || !reflect.DeepEqual(got.Delta, observed) {
					t.Fatalf("policy was not canonical or observed delta was changed: %#v", got)
				}
				if !reflect.DeepEqual(selection, originalSelection) {
					t.Fatal("Apply mutated caller's selection")
				}
			})
		}
		t.Run(string(category)+"/default", func(t *testing.T) {
			got, err := decision.Apply(observed, model.Options{})
			want := model.Clean
			if slices.Contains(categories, category) {
				want = model.ChangesDetected
			}
			if err != nil || got.Decision != want || !reflect.DeepEqual(got.Policy.FailOn, categories) || !reflect.DeepEqual(got.Delta, observed) {
				t.Fatalf("default policy: got %#v, %v; want %q with all changed categories", got, err, want)
			}
		})
	}
}

func TestApplyFrozenReports(t *testing.T) {
	// These independently authored contract examples retain every record,
	// context, attribute, count, version change and provenance declaration.
	for _, name := range []string{"report-changes", "report-none", "report-unchanged", "report-incomparable", "report-incomparable-unchanged"} {
		t.Run(name, func(t *testing.T) {
			want := readJSON[model.Report](t, "testdata/provenance/synthetic/"+name+".json")
			got, err := decision.Apply(want.Delta, model.Options{FailOn: want.Policy.FailOn})
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("full report differs from frozen contract\ngot: %#v, %v\nwant: %#v", got, err, want)
			}
		})
	}
	observed := readJSON[model.Report](t, "testdata/provenance/synthetic/report-changes.json").Delta
	before, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range [][]model.Category{nil, {}, {model.ContextChanged}, {model.StatusChanged, model.New}} {
		if _, err := decision.Apply(observed, model.Options{FailOn: selection}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := json.Marshal(observed)
	if err != nil || string(before) != string(after) {
		t.Fatal("applying policy mutated the original observed data")
	}
}

func TestIncomparableAlwaysWins(t *testing.T) {
	limitations := []struct {
		name   string
		mutate func(*model.Metadata, *model.Metadata)
	}{
		{"scanner", func(_, after *model.Metadata) { after.Scanner.Revision = "another-producer" }},
		{"database", func(_, after *model.Metadata) { after.Database.SHA256 = strings.Repeat("d", 64) }},
		{"scope", func(_, after *model.Metadata) { after.Coverage.ScopeSHA256 = strings.Repeat("e", 64) }},
		{"baseline incomplete", func(before, _ *model.Metadata) { before.Coverage.Complete = false }},
		{"candidate incomplete", func(_, after *model.Metadata) { after.Coverage.Complete = false }},
	}
	limitations = append(limitations, struct {
		name   string
		mutate func(*model.Metadata, *model.Metadata)
	}{"all", func(before, after *model.Metadata) {
		for _, limitation := range limitations[:5] {
			limitation.mutate(before, after)
		}
	}})
	for _, limitation := range limitations {
		for _, rows := range []string{"empty", "unchanged", "changed"} {
			for _, policy := range []struct {
				name string
				opts model.Options
			}{{"default", model.Options{}}, {"none", model.Options{FailOn: []model.Category{}}}, {"selected", model.Options{FailOn: []model.Category{model.New}}}} {
				t.Run(limitation.name+"/"+rows+"/"+policy.name, func(t *testing.T) {
					before, after := document("1"), document("1")
					issue := model.Issue{ID: "CVE-2026-1234", Status: model.Ignored}
					if rows == "unchanged" {
						before, after = document("1", issue), document("1", issue)
					} else if rows == "changed" {
						after = document("1", issue)
					}
					beforeMeta, afterMeta := metadata(), metadata()
					limitation.mutate(&beforeMeta, &afterMeta)
					observed := compare(t, before, after, beforeMeta, afterMeta)
					got, err := decision.Apply(observed, policy.opts)
					if err != nil || got.Decision != model.Incomparable || decision.ExitCode(got.Decision, err) != 3 || !reflect.DeepEqual(got.Delta, observed) {
						t.Fatalf("incomparability lost or observed data changed: %#v, %v", got, err)
					}
				})
			}
		}
	}
}

func TestInvalidOptionsReturnNoReport(t *testing.T) {
	invalid := [][]model.Category{
		{"unknown"}, {""}, {model.Unchanged}, {"none"},
		{model.New, model.New}, {model.ContextChanged, model.New, model.ContextChanged},
		{"none", model.New}, {model.New, "none"}, {"none", "none"},
		{"New"}, {" new"}, {"new "}, {model.New, "status_changed,context_changed"},
	}
	for _, incomparable := range []bool{false, true} {
		for _, selection := range invalid {
			t.Run(fmt.Sprintf("incomparable=%t/%q", incomparable, selection), func(t *testing.T) {
				observed := oneCategory(t, model.New)
				if incomparable {
					meta := metadata()
					meta.Coverage.Complete = false
					observed = compare(t, document("1"), document("1"), metadata(), meta)
				}
				got, err := decision.Apply(observed, model.Options{FailOn: selection})
				if err == nil || !reflect.DeepEqual(got, model.Report{}) || decision.ExitCode(got.Decision, err) != 2 {
					t.Fatalf("invalid options did not return only error: %#v, %v", got, err)
				}
			})
		}
	}
}

func TestPolicyOwnsItsSelection(t *testing.T) {
	selection := []model.Category{model.ContextChanged, model.New}
	got, err := decision.Apply(oneCategory(t, model.New), model.Options{FailOn: selection})
	if err != nil {
		t.Fatal(err)
	}
	got.Policy.FailOn[0] = model.StatusChanged
	if !reflect.DeepEqual(selection, []model.Category{model.ContextChanged, model.New}) {
		t.Fatal("report policy aliases caller options")
	}
	got, err = decision.Apply(oneCategory(t, model.New), model.Options{})
	if err != nil || !reflect.DeepEqual(got.Policy.FailOn, categories) {
		t.Fatal("previous policy mutation affected default policy")
	}
}
