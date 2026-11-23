// SPDX-License-Identifier: Apache-2.0

// Package delta compares validated reports as observed producer claims. It does
// not determine remediation, applicability or vulnerability risk.
package delta

import (
	"fmt"
	"slices"
	"strings"

	"github.com/firmdura/cvedelta/internal/model"
)

// Compare accounts for every finding identity in the union of baseline and
// candidate. Configuration mismatches and invalid Inputs return no delta.
// Other provenance limitations accompany the observed changes in Reasons.
func Compare(baseline, candidate model.Input) (model.Delta, error) {
	if !baseline.Valid() {
		return model.Delta{}, fmt.Errorf("baseline: invalid Input")
	}
	if !candidate.Valid() {
		return model.Delta{}, fmt.Errorf("candidate: invalid Input")
	}
	beforeMeta, afterMeta := baseline.Metadata(), candidate.Metadata()
	if beforeMeta.Firmware.ConfigurationID != afterMeta.Firmware.ConfigurationID {
		return model.Delta{}, fmt.Errorf("firmware.configuration_id: baseline and candidate differ")
	}
	result := model.Delta{
		SchemaVersion:           model.SchemaVersion,
		Baseline:                beforeMeta,
		Candidate:               afterMeta,
		Reasons:                 comparabilityReasons(beforeMeta, afterMeta),
		Records:                 []model.Record{},
		ComponentVersionChanges: []model.ComponentVersionChange{},
	}
	result.Comparable = len(result.Reasons) == 0

	// Document returns an owned deep copy, so contexts can retain attribute
	// pointers without exposing either immutable Input to output mutations.
	afterComponents := make(map[model.ComponentID]model.Component)
	for _, component := range candidate.Document().Components {
		afterComponents[componentID(component)] = component
	}
	for _, before := range baseline.Document().Components {
		id := componentID(before)
		after, present := afterComponents[id]
		if !present {
			for _, issue := range before.Issues {
				addRecord(&result, singleSided(id, before.Version, issue, false, model.ComponentAbsent))
			}
			continue
		}
		if before.Version != after.Version {
			result.ComponentVersionChanges = append(result.ComponentVersionChanges, model.ComponentVersionChange{
				Component: id, Before: before.Version, After: after.Version,
			})
		}
		compareComponent(&result, id, before, after)
		delete(afterComponents, id)
	}
	for id, after := range afterComponents {
		for _, issue := range after.Issues {
			addRecord(&result, singleSided(id, after.Version, issue, true, model.ComponentAbsent))
		}
	}
	slices.SortFunc(result.Records, func(a, b model.Record) int {
		if order := compareID(a.Component, b.Component); order != 0 {
			return order
		}
		return strings.Compare(a.CVEID, b.CVEID)
	})
	slices.SortFunc(result.ComponentVersionChanges, func(a, b model.ComponentVersionChange) int {
		return compareID(a.Component, b.Component)
	})
	return result, nil
}

func componentID(component model.Component) model.ComponentID {
	return model.ComponentID{Layer: component.Layer, Name: component.Name}
}

func compareID(a, b model.ComponentID) int {
	if order := strings.Compare(a.Layer, b.Layer); order != 0 {
		return order
	}
	return strings.Compare(a.Name, b.Name)
}

func compareComponent(result *model.Delta, id model.ComponentID, before, after model.Component) {
	afterIssues := make(map[string]model.Issue, len(after.Issues))
	for _, issue := range after.Issues {
		afterIssues[issue.ID] = issue
	}
	for _, issue := range before.Issues {
		other, present := afterIssues[issue.ID]
		if !present {
			addRecord(result, singleSided(id, before.Version, issue, false, model.FindingAbsent))
			continue
		}
		record := model.Record{
			Component: id, CVEID: issue.ID, Category: model.Unchanged,
			Before: context(before.Version, issue), After: context(after.Version, other),
		}
		record.ChangedFields = changedFields(*record.Before, *record.After)
		if issue.Status != other.Status {
			record.Category = model.StatusChanged
		} else if len(record.ChangedFields) != 0 {
			record.Category = model.ContextChanged
		}
		addRecord(result, record)
		delete(afterIssues, issue.ID)
	}
	for _, issue := range afterIssues {
		addRecord(result, singleSided(id, after.Version, issue, true, model.FindingAbsent))
	}
}

func context(version string, issue model.Issue) *model.Context {
	return &model.Context{Version: version, Status: issue.Status, Attributes: issue.Attributes}
}

func singleSided(id model.ComponentID, version string, issue model.Issue, added bool, reason model.AbsenceReason) model.Record {
	record := model.Record{
		Component: id, CVEID: issue.ID, Category: model.NoLongerReported,
		AbsenceReason: &reason, ChangedFields: []string{},
	}
	if added {
		record.Category = model.New
		record.After = context(version, issue)
	} else {
		record.Before = context(version, issue)
	}
	return record
}

func addRecord(result *model.Delta, record model.Record) {
	result.Records = append(result.Records, record)
	switch record.Category {
	case model.New:
		result.Counts.New++
	case model.NoLongerReported:
		result.Counts.NoLongerReported++
	case model.StatusChanged:
		result.Counts.StatusChanged++
	case model.ContextChanged:
		result.Counts.ContextChanged++
	case model.Unchanged:
		result.Counts.Unchanged++
	}
}

func changedFields(before, after model.Context) []string {
	// Collect on the stack so an unchanged finding needs no backing array.
	var scratch [12]string
	fields := scratch[:0]
	if before.Version != after.Version {
		fields = append(fields, "version")
	}
	if before.Status != after.Status {
		fields = append(fields, "status")
	}
	a, b := before.Attributes, after.Attributes
	for _, field := range []struct {
		name          string
		before, after *string
	}{
		{"detail", a.Detail, b.Detail},
		{"description", a.Description, b.Description},
		{"summary", a.Summary, b.Summary},
		{"link", a.Link, b.Link},
		{"modified", a.Modified, b.Modified},
		{"scorev2", a.ScoreV2, b.ScoreV2},
		{"scorev3", a.ScoreV3, b.ScoreV3},
		{"scorev4", a.ScoreV4, b.ScoreV4},
		{"vector", a.Vector, b.Vector},
		{"vectorString", a.VectorString, b.VectorString},
	} {
		if differentText(field.before, field.after) {
			fields = append(fields, field.name)
		}
	}
	return slices.Clone(fields)
}

func differentText(a, b *string) bool {
	if a == nil || b == nil {
		return a != b
	}
	return *a != *b
}

func comparabilityReasons(before, after model.Metadata) []model.Reason {
	reasons := []model.Reason{}
	for _, limitation := range []struct {
		applies bool
		code    model.ReasonCode
		message string
	}{
		{before.Scanner.Revision != after.Scanner.Revision, model.ScannerRevisionChanged, "Scanner revisions differ."},
		{before.Database.SHA256 != after.Database.SHA256, model.DatabaseChanged, "Database snapshot hashes differ."},
		{before.Coverage.ScopeSHA256 != after.Coverage.ScopeSHA256, model.CoverageScopeChanged, "Coverage scope hashes differ."},
		{!before.Coverage.Complete, model.BaselineCoverageIncomplete, "Baseline coverage is incomplete."},
		{!after.Coverage.Complete, model.CandidateCoverageIncomplete, "Candidate coverage is incomplete."},
	} {
		if limitation.applies {
			reasons = append(reasons, model.Reason{Code: limitation.code, Message: limitation.message})
		}
	}
	return reasons
}
