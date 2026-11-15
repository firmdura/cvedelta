// SPDX-License-Identifier: Apache-2.0

// Package model defines the version-1 contracts shared by CVEDelta feature packages.
// It performs no I/O and assigns no security meaning to a producer's status labels.
package model

import "io"

const (
	ReportVersion          = "1"
	SchemaVersion          = 1
	ScannerName            = "yocto-cve-check"
	MaxReportBytes   int64 = 64 << 20
	MaxMetadataBytes int64 = 1 << 20
	MaxComponents          = 100_000
	MaxFindings            = 1_000_000
)

type Status string

const (
	Patched   Status = "Patched"
	Unpatched Status = "Unpatched"
	Ignored   Status = "Ignored"
)

type Category string

const (
	New              Category = "new"
	NoLongerReported Category = "no_longer_reported"
	StatusChanged    Category = "status_changed"
	ContextChanged   Category = "context_changed"
	Unchanged        Category = "unchanged"
)

// Attributes preserves recognized source text exactly. A nil pointer means absent;
// a pointer to an empty string means explicitly present and empty. Null is invalid.
// Scores are producer strings, not numbers calculated or interpreted by CVEDelta.
type Attributes struct {
	Detail       *string `json:"detail,omitempty"`
	Description  *string `json:"description,omitempty"`
	Summary      *string `json:"summary,omitempty"`
	Link         *string `json:"link,omitempty"`
	Modified     *string `json:"modified,omitempty"`
	ScoreV2      *string `json:"scorev2,omitempty"`
	ScoreV3      *string `json:"scorev3,omitempty"`
	ScoreV4      *string `json:"scorev4,omitempty"`
	Vector       *string `json:"vector,omitempty"`
	VectorString *string `json:"vectorString,omitempty"`
}

type Issue struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	Attributes
}

type Component struct {
	Name    string  `json:"name"`
	Layer   string  `json:"layer"`
	Version string  `json:"version"`
	Issues  []Issue `json:"issue"`
}

type Document struct {
	Version    string      `json:"version"`
	Components []Component `json:"package"`
}

type Firmware struct {
	ConfigurationID string `json:"configuration_id"`
	BuildID         string `json:"build_id"`
	SourceRevision  string `json:"source_revision"`
}

type Scanner struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
}

type Database struct {
	SHA256 string `json:"sha256"`
}

type Coverage struct {
	ScopeSHA256 string `json:"scope_sha256"`
	Complete    bool   `json:"complete"`
}

type Metadata struct {
	SchemaVersion int      `json:"schema_version"`
	ReportSHA256  string   `json:"report_sha256"`
	Firmware      Firmware `json:"firmware"`
	Scanner       Scanner  `json:"scanner"`
	Database      Database `json:"database"`
	Coverage      Coverage `json:"coverage"`
}

// Input owns a defensive copy of validated data. Its zero value is invalid.
// Only the reader establishes that RawSHA256 hashes actual consumed report bytes.
// NewInput also permits in-memory construction for comparison tests and callers
// that already performed the strict stream validation described in contracts.md.
type Input struct {
	document  Document
	metadata  Metadata
	rawSHA256 string
	valid     bool
}

type ComponentID struct {
	Layer string `json:"layer"`
	Name  string `json:"name"`
}

type Context struct {
	Version    string     `json:"version"`
	Status     Status     `json:"status"`
	Attributes Attributes `json:"attributes"`
}

type AbsenceReason string

const (
	ComponentAbsent AbsenceReason = "component_absent"
	FindingAbsent   AbsenceReason = "finding_absent"
)

// Record has exactly one context for new/no_longer_reported, both otherwise.
// AbsenceReason describes the missing side, and is nil when both sides exist.
type Record struct {
	Component     ComponentID    `json:"component"`
	CVEID         string         `json:"cve_id"`
	Category      Category       `json:"category"`
	Before        *Context       `json:"before"`
	After         *Context       `json:"after"`
	AbsenceReason *AbsenceReason `json:"absence_reason"`
	ChangedFields []string       `json:"changed_fields"`
}

type Counts struct {
	New              int `json:"new"`
	NoLongerReported int `json:"no_longer_reported"`
	StatusChanged    int `json:"status_changed"`
	ContextChanged   int `json:"context_changed"`
	Unchanged        int `json:"unchanged"`
}

type ComponentVersionChange struct {
	Component ComponentID `json:"component"`
	Before    string      `json:"before"`
	After     string      `json:"after"`
}

type ReasonCode string

const (
	ScannerRevisionChanged      ReasonCode = "scanner_revision_changed"
	DatabaseChanged             ReasonCode = "database_changed"
	CoverageScopeChanged        ReasonCode = "coverage_scope_changed"
	BaselineCoverageIncomplete  ReasonCode = "baseline_coverage_incomplete"
	CandidateCoverageIncomplete ReasonCode = "candidate_coverage_incomplete"
)

type Reason struct {
	Code    ReasonCode `json:"code"`
	Message string     `json:"message"`
}

// Options distinguishes nil (default all changed categories) from empty (none).
// Unchanged is never a valid fail-on category. Policy stores the resolved list.
type Options struct{ FailOn []Category }
type Policy struct {
	FailOn []Category `json:"fail_on"`
}

type Decision string

const (
	Clean               Decision = "clean"
	ChangesDetected     Decision = "changes_detected"
	Incomparable        Decision = "incomparable"
	ExitClean                    = 0
	ExitChangesDetected          = 1
	ExitError                    = 2
	ExitIncomparable             = 3
)

// Delta is the observed result before change gating. Lists must be non-nil.
// It is an intermediate value, not a complete renderable schema-1 report.
type Delta struct {
	SchemaVersion           int                      `json:"schema_version"`
	Baseline                Metadata                 `json:"baseline"`
	Candidate               Metadata                 `json:"candidate"`
	Comparable              bool                     `json:"comparable"`
	Reasons                 []Reason                 `json:"reasons"`
	Records                 []Record                 `json:"records"`
	Counts                  Counts                   `json:"counts"`
	ComponentVersionChanges []ComponentVersionChange `json:"component_version_changes"`
}

// Report is the schema-1 output after policy resolution. Invalid input/tool/output
// failures return errors, never a Report decision. All lists encode as arrays.
type Report struct {
	Delta
	Policy   Policy   `json:"policy"`
	Decision Decision `json:"decision"`
}

// Feature implementations may expose matching functions; these interface contracts
// also allow adapters without introducing a dependency on the public facade.
type Reader interface {
	ReadInput(report io.Reader, metadata io.Reader) (Input, error)
}
type Comparator interface {
	Compare(baseline Input, candidate Input) (Delta, error)
}
type Decider interface {
	Apply(delta Delta, options Options) (Report, error)
}
type Renderer interface {
	WriteJSON(io.Writer, Report) error
	WriteMarkdown(io.Writer, Report) error
}
