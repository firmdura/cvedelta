// SPDX-License-Identifier: Apache-2.0

// Package cvedelta compares two Yocto cve-check version-1 reports offline.
// ReadInput validates each report and the caller's metadata describing its
// build and scan. Compare reports finding changes and uses that metadata to
// determine whether the inputs are comparable. It does not independently
// establish remediation, applicability or compliance. The library uses only
// supplied values and streams: it never opens files, makes network requests,
// prints, or exits.
package cvedelta

import (
	"io"

	"github.com/firmdura/cvedelta/internal/decision"
	"github.com/firmdura/cvedelta/internal/delta"
	"github.com/firmdura/cvedelta/internal/model"
	"github.com/firmdura/cvedelta/internal/reader"
	"github.com/firmdura/cvedelta/internal/render"
)

// Public aliases expose every input and output field type without internal
// imports. Input owns immutable validated data; its zero value is invalid.
// Document returns a deep copy, Metadata returns a value copy, and RawSHA256
// returns the report hash.
type (
	Input                  = model.Input
	Document               = model.Document
	Component              = model.Component
	Issue                  = model.Issue
	Attributes             = model.Attributes
	Metadata               = model.Metadata
	Firmware               = model.Firmware
	Scanner                = model.Scanner
	Database               = model.Database
	Coverage               = model.Coverage
	Status                 = model.Status
	Category               = model.Category
	ComponentID            = model.ComponentID
	Context                = model.Context
	AbsenceReason          = model.AbsenceReason
	Record                 = model.Record
	Counts                 = model.Counts
	ComponentVersionChange = model.ComponentVersionChange
	ReasonCode             = model.ReasonCode
	Reason                 = model.Reason
	Options                = model.Options
	Policy                 = model.Policy
	Decision               = model.Decision
	Delta                  = model.Delta
	Report                 = model.Report
)

const (
	ReportVersion    = model.ReportVersion
	SchemaVersion    = model.SchemaVersion
	ScannerName      = model.ScannerName
	MaxReportBytes   = model.MaxReportBytes
	MaxMetadataBytes = model.MaxMetadataBytes
	MaxComponents    = model.MaxComponents
	MaxFindings      = model.MaxFindings

	Patched   = model.Patched
	Unpatched = model.Unpatched
	Ignored   = model.Ignored

	New              = model.New
	NoLongerReported = model.NoLongerReported
	StatusChanged    = model.StatusChanged
	ContextChanged   = model.ContextChanged
	Unchanged        = model.Unchanged

	ComponentAbsent = model.ComponentAbsent
	FindingAbsent   = model.FindingAbsent

	ScannerRevisionChanged      = model.ScannerRevisionChanged
	DatabaseChanged             = model.DatabaseChanged
	CoverageScopeChanged        = model.CoverageScopeChanged
	BaselineCoverageIncomplete  = model.BaselineCoverageIncomplete
	CandidateCoverageIncomplete = model.CandidateCoverageIncomplete

	Clean           = model.Clean
	ChangesDetected = model.ChangesDetected
	Incomparable    = model.Incomparable

	ExitClean           = model.ExitClean
	ExitChangesDetected = model.ExitChangesDetected
	ExitError           = model.ExitError
	ExitIncomparable    = model.ExitIncomparable
)

// ReadInput strictly validates both JSON streams, checks the raw report SHA-256
// against metadata, and returns an Input that owns immutable validated data.
// The caller's database and coverage hashes are declarations, not independently
// verified build evidence. ReadInput does not close either stream. I/O and JSON
// syntax errors retain their types for errors.Is and errors.As.
func ReadInput(report io.Reader, metadata io.Reader) (Input, error) {
	return reader.ReadInput(report, metadata)
}

// Compare returns all finding records and a decision based on the inputs and
// selected change categories. A nil Options.FailOn selects all four changed
// categories; a non-nil empty slice selects none. Unknown categories, duplicates
// and Unchanged return an error, as do invalid Inputs or different configuration
// IDs. Differences in scanner revision, database hash or coverage-policy hash,
// and incomplete coverage, yield Incomparable even when no change categories
// are selected. Returned report data do not alias either Input.
func Compare(baseline Input, candidate Input, options Options) (Report, error) {
	observed, err := delta.Compare(baseline, candidate)
	if err != nil {
		return Report{}, err
	}
	return decision.Apply(observed, options)
}

// WriteJSON validates and writes deterministic schema-1 JSON with a final
// newline. encoding/json can decode it into Report without internal imports.
// Writer errors are preserved; a failed write may leave partial output.
func WriteJSON(w io.Writer, report Report) error { return render.WriteJSON(w, report) }

// WriteMarkdown validates and writes the complete report as Markdown.
// Untrusted source text is escaped, and source URLs appear as text rather than
// active links. Writer errors are preserved; a failed write may leave partial
// output.
func WriteMarkdown(w io.Writer, report Report) error { return render.WriteMarkdown(w, report) }
