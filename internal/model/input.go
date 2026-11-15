// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	cvePattern  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NewInput checks semantic invariants and takes an owned copy. Stream syntax,
// key presence/types/duplicates, byte limits and raw hashing belong to the reader.
func NewInput(document Document, metadata Metadata, rawSHA256 string) (Input, error) {
	if document.Version != ReportVersion {
		return Input{}, fmt.Errorf("report.version: expected %q", ReportVersion)
	}
	if document.Components == nil {
		return Input{}, fmt.Errorf("report.package: required array")
	}
	if len(document.Components) > MaxComponents {
		return Input{}, fmt.Errorf("report.package: component limit exceeded")
	}
	if err := validateMetadata(metadata, rawSHA256); err != nil {
		return Input{}, err
	}
	seen := make(map[ComponentID]bool, len(document.Components))
	rows := 0
	for i, c := range document.Components {
		where := fmt.Sprintf("report.package[%d]", i)
		if strings.TrimSpace(c.Name) == "" || strings.TrimSpace(c.Layer) == "" || strings.TrimSpace(c.Version) == "" {
			return Input{}, fmt.Errorf("%s: name, layer and version must be nonempty", where)
		}
		key := ComponentID{Layer: c.Layer, Name: c.Name}
		if seen[key] {
			return Input{}, fmt.Errorf("%s: duplicate component identity", where)
		}
		seen[key] = true
		if c.Issues == nil {
			return Input{}, fmt.Errorf("%s.issue: required array", where)
		}
		rows += len(c.Issues)
		if rows > MaxFindings {
			return Input{}, fmt.Errorf("%s.issue: finding limit exceeded", where)
		}
		ids := make(map[string]bool, len(c.Issues))
		for j, issue := range c.Issues {
			if !cvePattern.MatchString(issue.ID) {
				return Input{}, fmt.Errorf("%s.issue[%d].id: invalid CVE identifier", where, j)
			}
			if ids[issue.ID] {
				return Input{}, fmt.Errorf("%s.issue[%d]: duplicate finding identity", where, j)
			}
			ids[issue.ID] = true
			switch issue.Status {
			case Patched, Unpatched, Ignored:
			default:
				return Input{}, fmt.Errorf("%s.issue[%d].status: unsupported status", where, j)
			}
		}
	}
	return Input{document: cloneDocument(document), metadata: metadata, rawSHA256: rawSHA256, valid: true}, nil
}

func validateMetadata(m Metadata, raw string) error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("metadata.schema_version: expected %d", SchemaVersion)
	}
	if !hashPattern.MatchString(raw) || !hashPattern.MatchString(m.ReportSHA256) || m.ReportSHA256 != raw {
		return fmt.Errorf("metadata.report_sha256: invalid hash or report checksum mismatch")
	}
	if strings.TrimSpace(m.Firmware.ConfigurationID) == "" || strings.TrimSpace(m.Firmware.BuildID) == "" || strings.TrimSpace(m.Firmware.SourceRevision) == "" {
		return fmt.Errorf("metadata.firmware: all fields must be nonempty")
	}
	if m.Scanner.Name != ScannerName || strings.TrimSpace(m.Scanner.Revision) == "" {
		return fmt.Errorf("metadata.scanner: expected yocto-cve-check and nonempty revision")
	}
	if !hashPattern.MatchString(m.Database.SHA256) {
		return fmt.Errorf("metadata.database.sha256: expected lowercase SHA-256")
	}
	if !hashPattern.MatchString(m.Coverage.ScopeSHA256) {
		return fmt.Errorf("metadata.coverage.scope_sha256: expected lowercase SHA-256")
	}
	return nil
}

func (i Input) Valid() bool        { return i.valid }
func (i Input) Metadata() Metadata { return i.metadata }
func (i Input) RawSHA256() string  { return i.rawSHA256 }
func (i Input) Document() Document { return cloneDocument(i.document) }

func cloneDocument(d Document) Document {
	if d.Components == nil {
		return d
	}
	out := Document{Version: d.Version, Components: make([]Component, len(d.Components))}
	for n, c := range d.Components {
		out.Components[n] = c
		if c.Issues == nil {
			continue
		}
		out.Components[n].Issues = make([]Issue, len(c.Issues))
		for j, issue := range c.Issues {
			out.Components[n].Issues[j] = issue
			out.Components[n].Issues[j].Attributes = cloneAttributes(issue.Attributes)
		}
	}
	return out
}

func cloneAttributes(a Attributes) Attributes {
	copyString := func(s *string) *string {
		if s == nil {
			return nil
		}
		v := *s
		return &v
	}
	return Attributes{Detail: copyString(a.Detail), Description: copyString(a.Description), Summary: copyString(a.Summary), Link: copyString(a.Link), Modified: copyString(a.Modified), ScoreV2: copyString(a.ScoreV2), ScoreV3: copyString(a.ScoreV3), ScoreV4: copyString(a.ScoreV4), Vector: copyString(a.Vector), VectorString: copyString(a.VectorString)}
}
