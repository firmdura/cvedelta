// SPDX-License-Identifier: Apache-2.0

package delta_test

import (
	"reflect"
	"testing"

	"github.com/firmdura/cvedelta/internal/model"
)

func TestEachRecognizedAttribute(t *testing.T) {
	attributes := []struct {
		name string
		set  func(*model.Attributes, *string)
	}{
		{"detail", func(a *model.Attributes, v *string) { a.Detail = v }},
		{"description", func(a *model.Attributes, v *string) { a.Description = v }},
		{"summary", func(a *model.Attributes, v *string) { a.Summary = v }},
		{"link", func(a *model.Attributes, v *string) { a.Link = v }},
		{"modified", func(a *model.Attributes, v *string) { a.Modified = v }},
		{"scorev2", func(a *model.Attributes, v *string) { a.ScoreV2 = v }},
		{"scorev3", func(a *model.Attributes, v *string) { a.ScoreV3 = v }},
		{"scorev4", func(a *model.Attributes, v *string) { a.ScoreV4 = v }},
		{"vector", func(a *model.Attributes, v *string) { a.Vector = v }},
		{"vectorString", func(a *model.Attributes, v *string) { a.VectorString = v }},
	}
	for _, attribute := range attributes {
		for _, tc := range []struct {
			name          string
			before, after *string
			changed       bool
		}{
			{"both absent", nil, nil, false},
			{"absent to empty", nil, text(""), true},
			{"empty to absent", text(""), nil, true},
			{"equal distinct pointers", text("same"), text("same"), false},
			{"both empty", text(""), text(""), false},
			{"different text", text("reported \"old\"\nreason"), text("reported \"new\"\nreason"), true},
			{"exact whitespace", text("same"), text("same "), true},
		} {
			t.Run(attribute.name+"/"+tc.name, func(t *testing.T) {
				b, a := issue("CVE-2099-0001", model.Ignored), issue("CVE-2099-0001", model.Ignored)
				attribute.set(&b.Attributes, tc.before)
				attribute.set(&a.Attributes, tc.after)
				before := construct(t, document(component("meta", "component", "1", b)), metadata())
				after := construct(t, document(component("meta", "component", "1", a)), metadata())
				got := compare(t, before, after)
				r := got.Records[0]
				wantCategory, wantFields := model.Unchanged, []string{}
				if tc.changed {
					wantCategory, wantFields = model.ContextChanged, []string{attribute.name}
				}
				if r.Category != wantCategory || !reflect.DeepEqual(r.ChangedFields, wantFields) || r.AbsenceReason != nil {
					t.Fatalf("unexpected attribute comparison: %#v", r)
				}
				if !reflect.DeepEqual(*r.Before, model.Context{Version: "1", Status: model.Ignored, Attributes: b.Attributes}) ||
					!reflect.DeepEqual(*r.After, model.Context{Version: "1", Status: model.Ignored, Attributes: a.Attributes}) {
					t.Fatal("attribute presence or source text was not preserved")
				}
				assertUnion(t, before, after, got)
			})
		}
	}
}

func TestAllStatusTransitions(t *testing.T) {
	for _, b := range []model.Status{model.Patched, model.Unpatched, model.Ignored} {
		for _, a := range []model.Status{model.Patched, model.Unpatched, model.Ignored} {
			t.Run(string(b)+"/"+string(a), func(t *testing.T) {
				before := construct(t, document(component("meta", "component", "1", issue("CVE-2099-0001", b))), metadata())
				after := construct(t, document(component("meta", "component", "1", issue("CVE-2099-0001", a))), metadata())
				got := compare(t, before, after)
				r := got.Records[0]
				category, fields := model.Unchanged, []string{}
				if a != b {
					category, fields = model.StatusChanged, []string{"status"}
				}
				if r.Category != category || !reflect.DeepEqual(r.ChangedFields, fields) || r.Before.Status != b || r.After.Status != a {
					t.Fatalf("status claim reinterpreted: %#v", r)
				}
				assertUnion(t, before, after, got)
			})
		}
	}
}

func TestStatusPrecedenceRetainsEveryContextChange(t *testing.T) {
	b := issue("CVE-2099-0001", model.Patched)
	a := issue("CVE-2099-0001", model.Ignored)
	a.Attributes = model.Attributes{
		Detail: text(""), Description: text("reported description"), Summary: text("summary"),
		Link: text("https://example.invalid/\"quoted\"\nlink"), Modified: text("producer date"),
		ScoreV2: text("not interpreted"), ScoreV3: text("0"), ScoreV4: text("1"),
		Vector: text("vector"), VectorString: text("vector string"),
	}
	before := construct(t, document(component("meta", "component", "old", b)), metadata())
	after := construct(t, document(component("meta", "component", "new", a)), metadata())
	got := compare(t, before, after)
	r := got.Records[0]
	wantFields := []string{"version", "status", "detail", "description", "summary", "link", "modified", "scorev2", "scorev3", "scorev4", "vector", "vectorString"}
	if r.Category != model.StatusChanged || !reflect.DeepEqual(r.ChangedFields, wantFields) || !reflect.DeepEqual(r.After.Attributes, a.Attributes) {
		t.Fatalf("status change lost context changes: %#v", r)
	}
	if !reflect.DeepEqual(got.ComponentVersionChanges, []model.ComponentVersionChange{{Component: model.ComponentID{Layer: "meta", Name: "component"}, Before: "old", After: "new"}}) {
		t.Fatal("version change missing")
	}
	assertUnion(t, before, after, got)
}
