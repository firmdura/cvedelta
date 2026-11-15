# CVEDelta observed finding report

Schema version: 1

Comparable: true

Decision: changes_detected

The decision describes comparison and selected change gating, not a security assessment.

Provenance is caller-supplied, not independently attested. Matching provenance is necessary for comparability; it does not prove completeness, truth or applicability.

Statuses are literal producer claims. Patched and Ignored are not independent evidence of remediation, applicability or compliance. no_longer_reported means absence from the candidate report and does not establish a fix.

Quoted values are inert code text. Backslash escapes show newlines, controls, formatting characters and code/table/HTML delimiters; an empty quoted value differs from an absent attribute.

## Comparability reasons

None. The stated provenance comparability conditions match.

## Baseline provenance

- schema_version: 1
- report_sha256: `"4c31bd2d6800d5bbbfe83bc9f32a15d1a1513778eb11d584e79d3d276da4016b"`
- firmware.configuration_id: `"fixture:machine:distro"`
- firmware.build_id: `"baseline"`
- firmware.source_revision: `"original-synthetic-baseline"`
- scanner.name: `"yocto-cve-check"`
- scanner.revision: `"original-synthetic-producer-v1"`
- database.sha256: `"9d3d2c3b36e1fb4f8d9d00d12868fe09fe2a9e7d84c1463c317eb5c3733d53d0"`
- coverage.scope_sha256: `"5956c99a3a27507eec704e4a776e1732493363a85fdda67c0aeeece21df79789"`
- coverage.complete: true

## Candidate provenance

- schema_version: 1
- report_sha256: `"12ea1dbdb9f45256c5b4a5183a49a4ba5277f55150aa6a81677eed898f6340ce"`
- firmware.configuration_id: `"fixture:machine:distro"`
- firmware.build_id: `"candidate"`
- firmware.source_revision: `"original-synthetic-candidate"`
- scanner.name: `"yocto-cve-check"`
- scanner.revision: `"original-synthetic-producer-v1"`
- database.sha256: `"9d3d2c3b36e1fb4f8d9d00d12868fe09fe2a9e7d84c1463c317eb5c3733d53d0"`
- coverage.scope_sha256: `"5956c99a3a27507eec704e4a776e1732493363a85fdda67c0aeeece21df79789"`
- coverage.complete: true

## Selected change policy

fail_on: new, no_longer_reported, status_changed, context_changed

## Finding counts

| Category | Count |
| --- | ---: |
| new | 2 |
| no_longer_reported | 2 |
| status_changed | 1 |
| context_changed | 2 |
| unchanged | 3 |

Total finding records: 10

## Component version changes

| Layer | Component | Baseline version | Candidate version |
| --- | --- | --- | --- |
| `"meta"` | `"alpha"` | `"1.0"` | `"2.0"` |
| `"meta"` | `"empty"` | `"1.0"` | `"2.0"` |

## Finding records

### Record 1

- Layer: `"meta"`
- Component: `"added"`
- CVE ID: CVE-2099-0001
- Category: new
- Absence reason for missing baseline context: component_absent
- Changed fields: none

#### Baseline context

Absent.

#### Candidate context

- Version: `"1.0"`
- Reported status: Unpatched
- Recognized attributes: none present

### Record 2

- Layer: `"meta"`
- Component: `"alpha"`
- CVE ID: CVE-2099-0001
- Category: status_changed
- Absence reason: none (both contexts present)
- Changed fields: version, status, detail

#### Baseline context

- Version: `"1.0"`
- Reported status: Unpatched
- detail: `"old reported reason"`

#### Candidate context

- Version: `"2.0"`
- Reported status: Patched
- detail: `"reported \"new\" reason\nsecond line"`

### Record 3

- Layer: `"meta"`
- Component: `"alpha"`
- CVE ID: CVE-2099-0003
- Category: no_longer_reported
- Absence reason for missing candidate context: finding_absent
- Changed fields: none

#### Baseline context

- Version: `"1.0"`
- Reported status: Patched
- Recognized attributes: none present

#### Candidate context

Absent.

### Record 4

- Layer: `"meta"`
- Component: `"alpha"`
- CVE ID: CVE-2099-0004
- Category: new
- Absence reason for missing baseline context: finding_absent
- Changed fields: none

#### Baseline context

Absent.

#### Candidate context

- Version: `"2.0"`
- Reported status: Unpatched
- Recognized attributes: none present

### Record 5

- Layer: `"meta"`
- Component: `"alpha"`
- CVE ID: CVE-2099-0005
- Category: context_changed
- Absence reason: none (both contexts present)
- Changed fields: version

#### Baseline context

- Version: `"1.0"`
- Reported status: Unpatched
- summary: `"same text"`

#### Candidate context

- Version: `"2.0"`
- Reported status: Unpatched
- summary: `"same text"`

### Record 6

- Layer: `"meta"`
- Component: `"alpha-native"`
- CVE ID: CVE-2099-0001
- Category: unchanged
- Absence reason: none (both contexts present)
- Changed fields: none

#### Baseline context

- Version: `"1.0"`
- Reported status: Unpatched
- Recognized attributes: none present

#### Candidate context

- Version: `"1.0"`
- Reported status: Unpatched
- Recognized attributes: none present

### Record 7

- Layer: `"meta"`
- Component: `"gone"`
- CVE ID: CVE-2099-0001
- Category: no_longer_reported
- Absence reason for missing candidate context: component_absent
- Changed fields: none

#### Baseline context

- Version: `"1.0"`
- Reported status: Patched
- Recognized attributes: none present

#### Candidate context

Absent.

### Record 8

- Layer: `"meta"`
- Component: `"lib32-alpha"`
- CVE ID: CVE-2099-0001
- Category: unchanged
- Absence reason: none (both contexts present)
- Changed fields: none

#### Baseline context

- Version: `"1.0"`
- Reported status: Unpatched
- Recognized attributes: none present

#### Candidate context

- Version: `"1.0"`
- Reported status: Unpatched
- Recognized attributes: none present

### Record 9

- Layer: `"meta"`
- Component: `"stable"`
- CVE ID: CVE-2099-0001
- Category: unchanged
- Absence reason: none (both contexts present)
- Changed fields: none

#### Baseline context

- Version: `"1.0"`
- Reported status: Ignored
- description: `"Source claim only."`
- link: `"https://example.invalid/\u{3C}script\u{3E}\u{7C}\u{60}link\u{60}"`

#### Candidate context

- Version: `"1.0"`
- Reported status: Ignored
- description: `"Source claim only."`
- link: `"https://example.invalid/\u{3C}script\u{3E}\u{7C}\u{60}link\u{60}"`

### Record 10

- Layer: `"meta"`
- Component: `"stable"`
- CVE ID: CVE-2099-0002
- Category: context_changed
- Absence reason: none (both contexts present)
- Changed fields: detail

#### Baseline context

- Version: `"1.0"`
- Reported status: Unpatched
- Recognized attributes: none present

#### Candidate context

- Version: `"1.0"`
- Reported status: Unpatched
- detail: `""`
