// SPDX-License-Identifier: Apache-2.0

package decision_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/firmdura/cvedelta/internal/decision"
	"github.com/firmdura/cvedelta/internal/delta"
	"github.com/firmdura/cvedelta/internal/model"
)

func TestParseFailOn(t *testing.T) {
	cases := readJSON[struct {
		Valid []struct {
			Value string           `json:"value"`
			Want  []model.Category `json:"want"`
		} `json:"valid"`
		Invalid []string `json:"invalid"`
	}](t, "testdata/decision/selectors.json")
	for _, tc := range cases.Valid {
		t.Run(tc.Value, func(t *testing.T) {
			got, err := decision.ParseFailOn(tc.Value)
			if err != nil || !reflect.DeepEqual(got.FailOn, tc.Want) {
				t.Fatalf("ParseFailOn(%q) = %#v, %v; want %#v", tc.Value, got, err, tc.Want)
			}
			// The explicit none result must not become nil/default when applied.
			report, err := decision.Apply(oneCategory(t, model.New), got)
			if err != nil || !reflect.DeepEqual(report.Policy.FailOn, tc.Want) {
				t.Fatalf("parsed policy changed during Apply: %#v, %v", report.Policy, err)
			}
		})
	}
	for _, value := range cases.Invalid {
		t.Run("invalid/"+value, func(t *testing.T) {
			got, err := decision.ParseFailOn(value)
			if err == nil || !reflect.DeepEqual(got, model.Options{}) || decision.ExitCode("", err) != 2 {
				t.Fatalf("ParseFailOn(%q) = %#v, %v; want only error", value, got, err)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	for _, tc := range []struct {
		outcome model.Decision
		want    int
	}{
		{model.Clean, 0}, {model.ChangesDetected, 1}, {model.Incomparable, 3},
		{"", 2}, {"invalid", 2},
	} {
		t.Run(string(tc.outcome), func(t *testing.T) {
			if got := decision.ExitCode(tc.outcome, nil); got != tc.want {
				t.Fatalf("ExitCode(%q, nil) = %d, want %d", tc.outcome, got, tc.want)
			}
			for _, cause := range []string{"input", "options", "tool", "render", "output"} {
				if got := decision.ExitCode(tc.outcome, errors.New(cause)); got != 2 {
					t.Fatalf("%s error lost precedence over %q: got %d", cause, tc.outcome, got)
				}
			}
		})
	}
	if string(model.Clean) != "clean" || string(model.ChangesDetected) != "changes_detected" || string(model.Incomparable) != "incomparable" {
		t.Fatal("decision enum differs from the frozen contract")
	}
}

func TestComparisonErrorsRemainErrors(t *testing.T) {
	valid := input(t, document("1"), metadata())
	otherMeta := metadata()
	otherMeta.Firmware.ConfigurationID += "-other"
	otherMeta.Coverage.Complete = false
	other := input(t, document("1"), otherMeta)
	for _, tc := range []struct {
		name          string
		before, after model.Input
	}{
		{"invalid baseline", model.Input{}, valid},
		{"invalid candidate", valid, model.Input{}},
		{"configuration mismatch", valid, other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The facade must propagate comparison errors and call Apply only
			// after a successful comparison. None cannot bypass that boundary.
			observed, err := delta.Compare(tc.before, tc.after)
			var report model.Report
			if err == nil {
				report, err = decision.Apply(observed, model.Options{FailOn: []model.Category{}})
			}
			if err == nil || !reflect.DeepEqual(report, model.Report{}) || decision.ExitCode(report.Decision, err) != 2 {
				t.Fatalf("upstream error became a report decision: %#v, %v", report, err)
			}
		})
	}
}
