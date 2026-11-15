// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/firmdura/cvedelta/internal/model"
)

var (
	cveID         = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	allCategories = []model.Category{model.New, model.NoLongerReported, model.StatusChanged, model.ContextChanged, model.Unchanged}
)

type attribute struct {
	name  string
	value *string
}

func attributes(a model.Attributes) []attribute {
	return []attribute{{"detail", a.Detail}, {"description", a.Description}, {"summary", a.Summary}, {"link", a.Link}, {"modified", a.Modified}, {"scorev2", a.ScoreV2}, {"scorev3", a.ScoreV3}, {"scorev4", a.ScoreV4}, {"vector", a.Vector}, {"vectorString", a.VectorString}}
}

func countValues(c model.Counts) [5]int {
	return [5]int{c.New, c.NoLongerReported, c.StatusChanged, c.ContextChanged, c.Unchanged}
}

// Validation checks the information carried by a Report, not the unavailable
// original inputs. In particular, provenance remains a caller declaration.
func validate(r model.Report) error {
	if r.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("schema_version: expected 1")
	}
	if r.Reasons == nil || r.Records == nil || r.ComponentVersionChanges == nil || r.Policy.FailOn == nil {
		return fmt.Errorf("reasons, records, component_version_changes and policy.fail_on must be resolved arrays")
	}
	for _, m := range []model.Metadata{r.Baseline, r.Candidate} {
		// Reuse the model's metadata semantics without asserting that this renderer
		// consumed source bytes or verified their hashes.
		if _, err := model.NewInput(model.Document{Version: model.ReportVersion, Components: []model.Component{}}, m, m.ReportSHA256); err != nil {
			return err
		}
		for _, s := range []string{m.Firmware.ConfigurationID, m.Firmware.BuildID, m.Firmware.SourceRevision, m.Scanner.Revision} {
			if !utf8.ValidString(s) {
				return fmt.Errorf("metadata: invalid UTF-8")
			}
		}
	}
	if r.Baseline.Firmware.ConfigurationID != r.Candidate.Firmware.ConfigurationID {
		return fmt.Errorf("firmware.configuration_id: mismatch")
	}
	if err := validateReasons(r); err != nil {
		return err
	}
	selected := [4]bool{}
	last := -1
	for _, c := range r.Policy.FailOn {
		i := slices.Index(allCategories[:4], c)
		if i < 0 || i <= last {
			return fmt.Errorf("policy.fail_on: expected unique changed categories in canonical order")
		}
		selected[i], last = true, i
	}
	var counts [5]int
	type identity struct {
		component model.ComponentID
		cve       string
	}
	seen := make(map[identity]bool, len(r.Records))
	components := make(map[model.ComponentID]*componentState)
	for i, row := range r.Records {
		if err := validateRecord(row); err != nil {
			return fmt.Errorf("records[%d]: %w", i, err)
		}
		key := identity{row.Component, row.CVEID}
		if seen[key] {
			return fmt.Errorf("records[%d]: duplicate finding identity", i)
		}
		seen[key] = true
		counts[slices.Index(allCategories, row.Category)]++
		state := components[row.Component]
		if state == nil {
			state = &componentState{}
			components[row.Component] = state
		}
		if err := state.add(row); err != nil {
			return fmt.Errorf("records[%d]: %w", i, err)
		}
	}
	if counts != countValues(r.Counts) {
		return fmt.Errorf("counts: must account for every finding record")
	}
	changes := make(map[model.ComponentID]model.ComponentVersionChange, len(r.ComponentVersionChanges))
	for i, c := range r.ComponentVersionChanges {
		if !validComponent(c.Component) || !nonblank(c.Before) || !nonblank(c.After) || c.Before == c.After {
			return fmt.Errorf("component_version_changes[%d]: invalid identity or versions", i)
		}
		if _, exists := changes[c.Component]; exists {
			return fmt.Errorf("component_version_changes[%d]: duplicate component", i)
		}
		changes[c.Component] = c
		if state := components[c.Component]; state != nil {
			if err := state.before.set(c.Before); err != nil {
				return fmt.Errorf("component_version_changes[%d].before: %w", i, err)
			}
			if err := state.after.set(c.After); err != nil {
				return fmt.Errorf("component_version_changes[%d].after: %w", i, err)
			}
		}
	}
	for id, state := range components {
		if state.before.version != "" && state.after.version != "" && state.before.version != state.after.version {
			if _, ok := changes[id]; !ok {
				return fmt.Errorf("component_version_changes: missing observed version change")
			}
		}
	}
	wantDecision := model.Clean
	if !r.Comparable {
		wantDecision = model.Incomparable
	} else {
		for i, enabled := range selected {
			if enabled && counts[i] > 0 {
				wantDecision = model.ChangesDetected
			}
		}
	}
	if r.Decision != wantDecision {
		return fmt.Errorf("decision: unresolved or inconsistent with comparability and selected changes")
	}
	return nil
}

func validateReasons(r model.Report) error {
	conditions := []struct {
		code    model.ReasonCode
		applies bool
	}{
		{model.ScannerRevisionChanged, r.Baseline.Scanner.Revision != r.Candidate.Scanner.Revision},
		{model.DatabaseChanged, r.Baseline.Database.SHA256 != r.Candidate.Database.SHA256},
		{model.CoverageScopeChanged, r.Baseline.Coverage.ScopeSHA256 != r.Candidate.Coverage.ScopeSHA256},
		{model.BaselineCoverageIncomplete, !r.Baseline.Coverage.Complete},
		{model.CandidateCoverageIncomplete, !r.Candidate.Coverage.Complete},
	}
	n := 0
	for _, c := range conditions {
		if c.applies {
			if n >= len(r.Reasons) || r.Reasons[n].Code != c.code || !nonblank(r.Reasons[n].Message) {
				return fmt.Errorf("reasons: must explain every provenance limitation in canonical order")
			}
			n++
		}
	}
	if n != len(r.Reasons) || r.Comparable != (n == 0) {
		return fmt.Errorf("comparable/reasons: inconsistent with provenance")
	}
	return nil
}

func validateRecord(r model.Record) error {
	if !validComponent(r.Component) || !cveID.MatchString(r.CVEID) || !slices.Contains(allCategories, r.Category) {
		return fmt.Errorf("invalid component, CVE ID or category")
	}
	if r.ChangedFields == nil {
		return fmt.Errorf("changed_fields: required array")
	}
	for _, c := range []*model.Context{r.Before, r.After} {
		if c == nil {
			continue
		}
		if !nonblank(c.Version) || (c.Status != model.Patched && c.Status != model.Unpatched && c.Status != model.Ignored) {
			return fmt.Errorf("invalid context version or reported status")
		}
		for _, a := range attributes(c.Attributes) {
			if a.value != nil && !utf8.ValidString(*a.value) {
				return fmt.Errorf("attributes.%s: invalid UTF-8", a.name)
			}
		}
	}
	if r.Category == model.New || r.Category == model.NoLongerReported {
		if (r.Category == model.New && (r.Before != nil || r.After == nil)) || (r.Category == model.NoLongerReported && (r.Before == nil || r.After != nil)) {
			return fmt.Errorf("single-sided category has incorrect contexts")
		}
		if r.AbsenceReason == nil || (*r.AbsenceReason != model.ComponentAbsent && *r.AbsenceReason != model.FindingAbsent) || len(r.ChangedFields) != 0 {
			return fmt.Errorf("single-sided category requires absence reason and empty changed_fields")
		}
		return nil
	}
	if r.Before == nil || r.After == nil || r.AbsenceReason != nil {
		return fmt.Errorf("both-sided category requires both contexts and null absence_reason")
	}
	fields := changedFields(*r.Before, *r.After)
	want := model.Unchanged
	if r.Before.Status != r.After.Status {
		want = model.StatusChanged
	} else if len(fields) != 0 {
		want = model.ContextChanged
	}
	if r.Category != want || !slices.Equal(fields, r.ChangedFields) {
		return fmt.Errorf("category/changed_fields: must preserve all observed context changes in canonical order")
	}
	return nil
}

func changedFields(a, b model.Context) []string {
	fields := []string{}
	if a.Version != b.Version {
		fields = append(fields, "version")
	}
	if a.Status != b.Status {
		fields = append(fields, "status")
	}
	before, after := attributes(a.Attributes), attributes(b.Attributes)
	for i, old := range before {
		newValue := after[i].value
		if (old.value == nil) != (newValue == nil) || (old.value != nil && newValue != nil && *old.value != *newValue) {
			fields = append(fields, old.name)
		}
	}
	return fields
}

func nonblank(s string) bool                  { return utf8.ValidString(s) && strings.TrimSpace(s) != "" }
func validComponent(c model.ComponentID) bool { return nonblank(c.Layer) && nonblank(c.Name) }

type sideState struct {
	version string
	present bool
	absent  bool
}

func (s *sideState) set(version string) error {
	if s.absent || (s.version != "" && s.version != version) {
		return fmt.Errorf("contradictory component presence or version")
	}
	s.version = version
	s.present = true
	return nil
}

func (s *sideState) markAbsent() error {
	if s.present {
		return fmt.Errorf("component_absent contradicts a present component")
	}
	s.absent = true
	return nil
}

type componentState struct{ before, after sideState }

func (s *componentState) add(r model.Record) error {
	for i, c := range []*model.Context{r.Before, r.After} {
		side := &s.before
		if i == 1 {
			side = &s.after
		}
		if c != nil {
			if err := side.set(c.Version); err != nil {
				return err
			}
		} else if r.AbsenceReason != nil {
			if *r.AbsenceReason == model.ComponentAbsent {
				if err := side.markAbsent(); err != nil {
					return err
				}
			} else {
				if side.absent {
					return fmt.Errorf("finding_absent contradicts component_absent")
				}
				side.present = true
			}
		}
	}
	return nil
}
