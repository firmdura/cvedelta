// SPDX-License-Identifier: Apache-2.0

// Package decision applies change gating to validated observed deltas. It does
// not infer remediation or alter the findings and provenance being reported.
package decision

import (
	"fmt"
	"strings"

	"github.com/firmdura/cvedelta/internal/model"
)

var changedCategories = [...]model.Category{
	model.New, model.NoLongerReported, model.StatusChanged, model.ContextChanged,
}

// Apply resolves a successfully compared Delta without filtering or mutating it.
// Callers must propagate comparison errors instead of applying their zero Delta.
// A nil FailOn selects all four changed categories; a nonnil empty slice selects
// none. Unknown, unchanged and duplicate categories return an error and no report,
// even for incomparable input. Policy.FailOn is stored in canonical category order.
// Incomparability always takes precedence over change gating, including none.
func Apply(observed model.Delta, options model.Options) (model.Report, error) {
	policy, err := resolvePolicy(options.FailOn)
	if err != nil {
		return model.Report{}, err
	}
	report := model.Report{Delta: observed, Policy: policy, Decision: model.Clean}
	if !observed.Comparable {
		report.Decision = model.Incomparable
		return report, nil
	}
	counts := [...]int{
		observed.Counts.New, observed.Counts.NoLongerReported,
		observed.Counts.StatusChanged, observed.Counts.ContextChanged,
	}
	for i, category := range changedCategories {
		for _, selected := range policy.FailOn {
			if category == selected && counts[i] > 0 {
				report.Decision = model.ChangesDetected
				return report, nil
			}
		}
	}
	return report, nil
}

// ParseFailOn parses an explicitly supplied --fail-on value: an exact comma-
// separated list of changed category names, or "none" alone. It rejects empty
// tokens, whitespace, unknown names, unchanged, repetitions and mixed none.
// For an omitted flag, callers use model.Options{} to retain the default policy.
// The returned selection is canonical and "none" yields a nonnil empty FailOn.
func ParseFailOn(value string) (model.Options, error) {
	if value == "none" {
		return model.Options{FailOn: []model.Category{}}, nil
	}
	tokens := strings.Split(value, ",")
	selection := make([]model.Category, len(tokens))
	for i, token := range tokens {
		selection[i] = model.Category(token)
	}
	policy, err := resolvePolicy(selection)
	if err != nil {
		return model.Options{}, err
	}
	return model.Options{FailOn: policy.FailOn}, nil
}

// ExitCode maps clean, changes_detected and incomparable to 0, 1 and 3.
// Any input, option, tool, render or output error takes precedence and maps to 2;
// an unresolved or unknown decision also maps to 2. It never prints or exits.
func ExitCode(outcome model.Decision, err error) int {
	if err != nil {
		return model.ExitError
	}
	switch outcome {
	case model.Clean:
		return model.ExitClean
	case model.ChangesDetected:
		return model.ExitChangesDetected
	case model.Incomparable:
		return model.ExitIncomparable
	default:
		return model.ExitError
	}
}

func resolvePolicy(selection []model.Category) (model.Policy, error) {
	selected := [len(changedCategories)]bool{}
	if selection == nil {
		for i := range selected {
			selected[i] = true
		}
	} else {
		for _, category := range selection {
			index := -1
			for i, known := range changedCategories {
				if category == known {
					index = i
					break
				}
			}
			if index == -1 {
				return model.Policy{}, fmt.Errorf("fail_on: invalid changed category %q", category)
			}
			if selected[index] {
				return model.Policy{}, fmt.Errorf("fail_on: repeated category %q", category)
			}
			selected[index] = true
		}
	}
	policy := model.Policy{FailOn: make([]model.Category, 0, len(changedCategories))}
	for i, category := range changedCategories {
		if selected[i] {
			policy.FailOn = append(policy.FailOn, category)
		}
	}
	return policy, nil
}
