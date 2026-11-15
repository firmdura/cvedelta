// SPDX-License-Identifier: Apache-2.0

package delta_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/firmdura/cvedelta/internal/model"
)

func TestExactIdentityAndLexicalOrdering(t *testing.T) {
	// These identities catch delimiter concatenation, trimming/case folding,
	// layer omission, native/multilib merging and numeric CVE sorting.
	ids := []model.ComponentID{
		{Layer: "a|b", Name: "c"}, {Layer: "a", Name: "b|c"},
		{Layer: "meta", Name: "alpha"}, {Layer: "meta", Name: "alpha-native"},
		{Layer: "meta", Name: "lib32-alpha"}, {Layer: "other", Name: "alpha"},
		{Layer: "meta", Name: "Alpha"}, {Layer: "meta", Name: " alpha"},
		{Layer: "Meta", Name: "alpha"}, {Layer: "meta ", Name: "alpha"},
	}
	bDoc, aDoc := document(), document()
	for n, id := range ids {
		bDoc.Components = append(bDoc.Components, component(id.Layer, id.Name, fmt.Sprintf("old-%d", n),
			issue("CVE-2099-9999", model.Patched), issue("CVE-2099-10000", model.Patched)))
		aDoc.Components = append(aDoc.Components, component(id.Layer, id.Name, fmt.Sprintf("new-%d", n),
			issue("CVE-2099-10000", model.Patched), issue("CVE-2099-9999", model.Patched)))
	}
	before, after := construct(t, bDoc, metadata()), construct(t, aDoc, metadata())
	got := compare(t, before, after)
	wantOrder := []model.ComponentID{
		{Layer: "Meta", Name: "alpha"}, {Layer: "a", Name: "b|c"}, {Layer: "a|b", Name: "c"},
		{Layer: "meta", Name: " alpha"}, {Layer: "meta", Name: "Alpha"}, {Layer: "meta", Name: "alpha"},
		{Layer: "meta", Name: "alpha-native"}, {Layer: "meta", Name: "lib32-alpha"},
		{Layer: "meta ", Name: "alpha"}, {Layer: "other", Name: "alpha"},
	}
	if len(got.Records) != len(ids)*2 || got.Counts != (model.Counts{ContextChanged: len(ids) * 2}) || len(got.ComponentVersionChanges) != len(ids) {
		t.Fatalf("merged identities or treated upgrade as new: %#v", got)
	}
	for n, id := range wantOrder {
		change := got.ComponentVersionChanges[n]
		if change.Component != id {
			t.Fatalf("version change order %d: %#v", n, change)
		}
		for j, cve := range []string{"CVE-2099-10000", "CVE-2099-9999"} {
			r := got.Records[n*2+j]
			if r.Component != id || r.CVEID != cve || r.Before.Version != change.Before || r.After.Version != change.After || !reflect.DeepEqual(r.ChangedFields, []string{"version"}) {
				t.Fatalf("identity/order/context mismatch at %d: %#v", n*2+j, r)
			}
		}
	}
	assertUnion(t, before, after, got)
}

func TestLayerRenameIsRemovalAndAddition(t *testing.T) {
	before := construct(t, document(component("old-layer", "alpha", "1", issue("CVE-2099-0001", model.Patched))), metadata())
	after := construct(t, document(component("new-layer", "alpha", "2", issue("CVE-2099-0001", model.Patched))), metadata())
	got := compare(t, before, after)
	if got.Counts != (model.Counts{New: 1, NoLongerReported: 1}) || len(got.ComponentVersionChanges) != 0 {
		t.Fatalf("layer rename was merged: %#v", got)
	}
	if got.Records[0].Component.Layer != "new-layer" || got.Records[0].Category != model.New || got.Records[1].Component.Layer != "old-layer" || got.Records[1].Category != model.NoLongerReported {
		t.Fatal("layer rename records are incorrect or unsorted")
	}
	for _, r := range got.Records {
		if r.AbsenceReason == nil || *r.AbsenceReason != model.ComponentAbsent || len(r.ChangedFields) != 0 {
			t.Fatal("layer rename lost absence details")
		}
	}
	assertUnion(t, before, after, got)
}

func TestBothAbsenceReasonsForAllStatuses(t *testing.T) {
	for _, added := range []bool{false, true} {
		for _, componentPresent := range []bool{false, true} {
			for _, status := range []model.Status{model.Patched, model.Unpatched, model.Ignored} {
				t.Run(fmt.Sprintf("added=%v/component-present=%v/%s", added, componentPresent, status), func(t *testing.T) {
					present := document(component("meta", "component", "reported-version", issue("CVE-2099-0001", status)))
					missing := document()
					reason := model.ComponentAbsent
					if componentPresent {
						missing = document(component("meta", "component", "other-version"))
						reason = model.FindingAbsent
					}
					bDoc, aDoc := present, missing
					category := model.NoLongerReported
					if added {
						bDoc, aDoc, category = missing, present, model.New
					}
					before, after := construct(t, bDoc, metadata()), construct(t, aDoc, metadata())
					got := compare(t, before, after)
					r := got.Records[0]
					if r.Category != category || r.AbsenceReason == nil || *r.AbsenceReason != reason || len(r.ChangedFields) != 0 {
						t.Fatalf("unexpected disappearance/addition semantics: %#v", r)
					}
					context := r.Before
					if added {
						context = r.After
						if r.Before != nil {
							t.Fatal("new finding has before context")
						}
					} else if r.After != nil {
						t.Fatal("no longer reported finding has after context")
					}
					if context == nil || context.Status != status || context.Version != "reported-version" {
						t.Fatal("surviving reported context lost")
					}
					wantVersionChanges := 0
					if componentPresent {
						wantVersionChanges = 1
					}
					if len(got.ComponentVersionChanges) != wantVersionChanges {
						t.Fatal("shared component version change missing, or absent component counted")
					}
					assertUnion(t, before, after, got)
				})
			}
		}
	}
}

func TestEmptyReportsAndIssueFreeComponentVersions(t *testing.T) {
	empty := construct(t, document(), metadata())
	populated := construct(t, document(component("meta", "component", "1", issue("CVE-2099-0001", model.Unpatched))), metadata())
	for _, tc := range []struct {
		name          string
		before, after model.Input
		counts        model.Counts
	}{
		{"both empty", empty, empty, model.Counts{}},
		{"empty baseline", empty, populated, model.Counts{New: 1}},
		{"empty candidate", populated, empty, model.Counts{NoLongerReported: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := compare(t, tc.before, tc.after)
			if !got.Comparable || got.Counts != tc.counts || len(got.ComponentVersionChanges) != 0 {
				t.Fatalf("unexpected empty report comparison: %#v", got)
			}
			assertUnion(t, tc.before, tc.after, got)
		})
	}
	before := construct(t, document(component("z", "same", "1"), component("a", "gone", "1"), component("a", "same", "2")), metadata())
	after := construct(t, document(component("a", "same", "3"), component("z", "same", "2"), component("a", "added", "1")), metadata())
	got := compare(t, before, after)
	wantVersions := []model.ComponentVersionChange{
		{Component: model.ComponentID{Layer: "a", Name: "same"}, Before: "2", After: "3"},
		{Component: model.ComponentID{Layer: "z", Name: "same"}, Before: "1", After: "2"},
	}
	if !reflect.DeepEqual(got.ComponentVersionChanges, wantVersions) || got.Counts != (model.Counts{}) || len(got.Records) != 0 {
		t.Fatalf("issue-free component versions incorrect: %#v", got)
	}
	assertUnion(t, before, after, got)
}
