// SPDX-License-Identifier: Apache-2.0

// Package reader validates the single supported Yocto report format and binds it
// to explicit caller-supplied provenance. It only consumes the supplied streams.
package reader

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/firmdura/cvedelta/internal/model"
)

// ReadInput reads bounded JSON documents and returns an owned, validated Input.
// The report hash covers every raw byte, including insignificant whitespace.
// Errors include a structural location and never include source values or keys.
func ReadInput(report io.Reader, metadata io.Reader) (model.Input, error) {
	raw, err := readBounded(report, model.MaxReportBytes, "report")
	if err != nil {
		return model.Input{}, err
	}
	document, err := readReport(raw)
	if err != nil {
		return model.Input{}, err
	}
	metaRaw, err := readBounded(metadata, model.MaxMetadataBytes, "metadata")
	if err != nil {
		return model.Input{}, err
	}
	meta, err := readMetadata(metaRaw)
	if err != nil {
		return model.Input{}, err
	}
	hash := sha256.Sum256(raw)
	return model.NewInput(document, meta, hex.EncodeToString(hash[:]))
}

func readBounded(r io.Reader, limit int64, path string) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%s: reader is nil", path)
	}
	// The extra byte detects overflow without consuming the rest of an oversized
	// stream. Reading to EOF also catches errors after an otherwise valid object.
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", path, err)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s: byte limit exceeded (%d bytes)", path, limit)
	}
	return raw, nil
}

type parser struct {
	decoder  *json.Decoder
	findings int
}

func newParser(raw []byte, path string) (*parser, error) {
	if err := validateText(raw, path); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return &parser{decoder: d}, nil
}

func (p *parser) token(path string) (json.Token, error) {
	t, err := p.decoder.Token()
	if err != nil {
		// SyntaxError includes only a byte/grammar description, not source bodies.
		return nil, fmt.Errorf("%s: invalid JSON: %w", path, err)
	}
	return t, nil
}

func (p *parser) delimiter(path string, want json.Delim) error {
	t, err := p.token(path)
	if err != nil {
		return err
	}
	if t != want {
		return fmt.Errorf("%s: expected %c", path, want)
	}
	return nil
}

// object checks decoded keys, so escaped spellings cannot hide duplicates.
// The callback consumes recognized fields; arbitrary metadata is traversed with
// the same duplicate checks but is never copied into the interpreted document.
func (p *parser) object(path string, required []string, extra bool, field func(string) (bool, error)) error {
	if err := p.delimiter(path, '{'); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for p.decoder.More() {
		t, err := p.token(path)
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok {
			return fmt.Errorf("%s: expected object key", path)
		}
		if seen[key] {
			return fmt.Errorf("%s: duplicate JSON object key", path)
		}
		seen[key] = true
		known, err := field(key)
		if err != nil {
			return err
		}
		if !known {
			if !extra {
				return fmt.Errorf("%s: unknown field", path)
			}
			if err := p.skip(path + ".<metadata>"); err != nil {
				return err
			}
		}
	}
	if err := p.delimiter(path, '}'); err != nil {
		return err
	}
	for _, name := range required {
		if !seen[name] {
			return fmt.Errorf("%s.%s: required field missing", path, name)
		}
	}
	return nil
}

func (p *parser) array(path string, limit int, item func(string) error) error {
	if err := p.delimiter(path, '['); err != nil {
		return err
	}
	for i := 0; p.decoder.More(); i++ {
		if i == limit {
			return fmt.Errorf("%s: count limit exceeded (%d items)", path, limit)
		}
		if err := item(fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return p.delimiter(path, ']')
}

func (p *parser) string(path string) (string, error) {
	t, err := p.token(path)
	if err != nil {
		return "", err
	}
	s, ok := t.(string)
	if !ok {
		return "", fmt.Errorf("%s: expected string", path)
	}
	return s, nil
}

func (p *parser) boolean(path string) (bool, error) {
	t, err := p.token(path)
	if err != nil {
		return false, err
	}
	b, ok := t.(bool)
	if !ok {
		return false, fmt.Errorf("%s: expected boolean", path)
	}
	return b, nil
}

func (p *parser) finish(path string) error {
	if _, err := p.decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("%s: trailing or malformed JSON after document: %w", path, err)
		}
		return fmt.Errorf("%s: trailing or malformed JSON after document", path)
	}
	return nil
}

// skip validates ignored JSON without retaining its data. An explicit stack
// handles deep nesting without exhausting the call stack. Keeping the path at
// the containing metadata field avoids reflecting arbitrary source key text or
// constructing unbounded diagnostic strings for deeply nested metadata.
func (p *parser) skip(path string) error {
	t, err := p.token(path)
	if err != nil {
		return err
	}
	type container struct {
		end  json.Delim
		keys map[string]bool // nil for arrays
	}
	var stack []container
	for {
		switch t {
		case json.Delim('{'):
			stack = append(stack, container{'}', make(map[string]bool)})
		case json.Delim('['):
			stack = append(stack, container{end: ']'})
		}
		for {
			if len(stack) == 0 {
				return nil
			}
			current := &stack[len(stack)-1]
			if !p.decoder.More() {
				if err := p.delimiter(path, current.end); err != nil {
					return err
				}
				stack = stack[:len(stack)-1]
				continue
			}
			if current.keys != nil {
				keyToken, err := p.token(path)
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("%s: expected object key", path)
				}
				if current.keys[key] {
					return fmt.Errorf("%s: duplicate JSON object key", path)
				}
				current.keys[key] = true
			}
			t, err = p.token(path)
			if err != nil {
				return err
			}
			break
		}
	}
}

func readReport(raw []byte) (model.Document, error) {
	p, err := newParser(raw, "report")
	if err != nil {
		return model.Document{}, err
	}
	d := model.Document{}
	err = p.object("report", []string{"version", "package"}, true, func(key string) (bool, error) {
		switch key {
		case "version":
			d.Version, err = p.string("report.version")
		case "package":
			d.Components = make([]model.Component, 0)
			err = p.array("report.package", model.MaxComponents, func(path string) error {
				c, err := p.component(path)
				if err == nil {
					d.Components = append(d.Components, c)
				}
				return err
			})
		default:
			return false, nil
		}
		return true, err
	})
	if err == nil {
		err = p.finish("report")
	}
	return d, err
}

func (p *parser) component(path string) (model.Component, error) {
	c := model.Component{}
	err := p.object(path, []string{"name", "layer", "version", "issue"}, true, func(key string) (bool, error) {
		var err error
		switch key {
		case "name":
			c.Name, err = p.string(path + ".name")
		case "layer":
			c.Layer, err = p.string(path + ".layer")
		case "version":
			c.Version, err = p.string(path + ".version")
		case "issue":
			c.Issues = make([]model.Issue, 0)
			err = p.array(path+".issue", model.MaxFindings, func(where string) error {
				if p.findings == model.MaxFindings {
					return fmt.Errorf("%s: finding limit exceeded", where)
				}
				p.findings++
				issue, err := p.issue(where)
				if err == nil {
					c.Issues = append(c.Issues, issue)
				}
				return err
			})
		default:
			return false, nil
		}
		return true, err
	})
	return c, err
}

func (p *parser) issue(path string) (model.Issue, error) {
	i := model.Issue{}
	err := p.object(path, []string{"id", "status"}, true, func(key string) (bool, error) {
		var target **string
		switch key {
		case "id":
			var err error
			i.ID, err = p.string(path + ".id")
			return true, err
		case "status":
			value, err := p.string(path + ".status")
			i.Status = model.Status(value)
			return true, err
		case "detail":
			target = &i.Detail
		case "description":
			target = &i.Description
		case "summary":
			target = &i.Summary
		case "link":
			target = &i.Link
		case "modified":
			target = &i.Modified
		case "scorev2":
			target = &i.ScoreV2
		case "scorev3":
			target = &i.ScoreV3
		case "scorev4":
			target = &i.ScoreV4
		case "vector":
			target = &i.Vector
		case "vectorString":
			target = &i.VectorString
		default:
			return false, nil
		}
		value, err := p.string(path + "." + key)
		if err == nil {
			*target = &value
		}
		return true, err
	})
	return i, err
}

func readMetadata(raw []byte) (model.Metadata, error) {
	p, err := newParser(raw, "metadata")
	if err != nil {
		return model.Metadata{}, err
	}
	m := model.Metadata{}
	err = p.object("metadata", []string{"schema_version", "report_sha256", "firmware", "scanner", "database", "coverage"}, false, func(key string) (bool, error) {
		switch key {
		case "schema_version":
			var t json.Token
			t, err = p.token("metadata.schema_version")
			if err == nil {
				if number, ok := t.(json.Number); !ok || !isOne(number) {
					err = fmt.Errorf("metadata.schema_version: expected integer 1")
				} else {
					m.SchemaVersion = model.SchemaVersion
				}
			}
		case "report_sha256":
			m.ReportSHA256, err = p.string("metadata.report_sha256")
		case "firmware":
			err = p.stringObject("metadata.firmware", []string{"configuration_id", "build_id", "source_revision"}, []*string{&m.Firmware.ConfigurationID, &m.Firmware.BuildID, &m.Firmware.SourceRevision})
		case "scanner":
			err = p.stringObject("metadata.scanner", []string{"name", "revision"}, []*string{&m.Scanner.Name, &m.Scanner.Revision})
		case "database":
			err = p.stringObject("metadata.database", []string{"sha256"}, []*string{&m.Database.SHA256})
		case "coverage":
			err = p.object("metadata.coverage", []string{"scope_sha256", "complete"}, false, func(key string) (bool, error) {
				switch key {
				case "scope_sha256":
					m.Coverage.ScopeSHA256, err = p.string("metadata.coverage.scope_sha256")
				case "complete":
					m.Coverage.Complete, err = p.boolean("metadata.coverage.complete")
				default:
					return false, nil
				}
				return true, err
			})
		default:
			return false, nil
		}
		return true, err
	})
	if err == nil {
		err = p.finish("metadata")
	}
	return m, err
}

func (p *parser) stringObject(path string, keys []string, targets []*string) error {
	return p.object(path, keys, false, func(key string) (bool, error) {
		for i, name := range keys {
			if key == name {
				value, err := p.string(path + "." + name)
				*targets[i] = value
				return true, err
			}
		}
		return false, nil
	})
}
