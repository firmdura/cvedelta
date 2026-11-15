// SPDX-License-Identifier: Apache-2.0

package main_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/firmdura/cvedelta/pkg/cvedelta"
)

var binary, root string

func TestMain(m *testing.M) {
	var err error
	root, err = filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// All compiled outputs remain under ignored dist, including when tests run
	// in the Linux container with a read-only source mount.
	if err = os.MkdirAll(filepath.Join(root, "dist"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	directory, err := os.MkdirTemp(filepath.Join(root, "dist"), "cli-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(directory, "cvedelta")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	// Verification does not depend on host Git ownership or VCS stamping.
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-buildvcs=false", "-o", binary, "./cmd/cvedelta")
	build.Dir = root
	output, err := build.CombinedOutput()
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build real CLI: %v\n%s", err, output)
		os.RemoveAll(directory)
		os.Exit(1)
	}
	status := m.Run()
	if err := os.RemoveAll(directory); err != nil && status == 0 {
		fmt.Fprintln(os.Stderr, err)
		status = 1
	}
	os.Exit(status)
}

func fixture(name string) string {
	return filepath.Join(root, "testdata", "provenance", "synthetic", name)
}

func compareArgs(before, beforeMeta, after, afterMeta string) []string {
	return []string{"compare", "--baseline", before, "--baseline-meta", beforeMeta,
		"--candidate", after, "--candidate-meta", afterMeta}
}

func defaults() []string {
	return compareArgs(fixture("baseline.json"), fixture("baseline.meta.json"), fixture("candidate.json"), fixture("candidate.meta.json"))
}

func run(t *testing.T, args []string) (int, []byte, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = root
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatal("CLI timed out", ctx.Err())
	}
	if err == nil {
		return 0, stdout.Bytes(), stderr.Bytes()
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return exit.ExitCode(), stdout.Bytes(), stderr.Bytes()
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func load(t *testing.T, path, metadata string) cvedelta.Input {
	t.Helper()
	input, err := cvedelta.ReadInput(bytes.NewReader(read(t, path)), bytes.NewReader(read(t, metadata)))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func decode(t *testing.T, output []byte) cvedelta.Report {
	t.Helper()
	var report cvedelta.Report
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("trailing output: %v", err)
	}
	return report
}

func TestProcessAllOutcomesAndLibraryParity(t *testing.T) {
	for _, tc := range []struct {
		name, before, beforeMeta, after, afterMeta string
		failOn                                     []cvedelta.Category
		exit                                       int
	}{
		{"identical", "baseline.json", "baseline.meta.json", "baseline.json", "baseline.meta.json", nil, 0},
		{"default changes", "baseline.json", "baseline.meta.json", "candidate.json", "candidate.meta.json", nil, 1},
		{"none", "baseline.json", "baseline.meta.json", "candidate.json", "candidate.meta.json", []cvedelta.Category{}, 0},
		{"selected", "baseline.json", "baseline.meta.json", "candidate.json", "candidate.meta.json", []cvedelta.Category{cvedelta.StatusChanged, cvedelta.New}, 1},
		{"configuration", "baseline.json", "baseline.meta.json", "candidate.json", "configuration-mismatch.meta.json", []cvedelta.Category{}, 2},
		{"checksum", "baseline.json", "baseline.meta.json", "candidate.json", "wrong-checksum.meta.json", []cvedelta.Category{}, 2},
		{"database beats none", "baseline.json", "baseline.meta.json", "candidate.json", "database.meta.json", []cvedelta.Category{}, 3},
		{"all limitations", "baseline.json", "baseline-incomplete.meta.json", "candidate.json", "all-incomparable.meta.json", []cvedelta.Category{}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := []string{fixture(tc.before), fixture(tc.beforeMeta), fixture(tc.after), fixture(tc.afterMeta)}
			snapshots := map[string][]byte{}
			for _, path := range paths {
				snapshots[path] = read(t, path)
			}
			args := compareArgs(paths[0], paths[1], paths[2], paths[3])
			if tc.failOn != nil {
				var categories []string
				for _, c := range tc.failOn {
					categories = append(categories, string(c))
				}
				value := strings.Join(categories, ",")
				if len(categories) == 0 {
					value = "none"
				}
				args = append(args, "--fail-on", value)
			}
			for _, format := range []string{"json", "markdown"} {
				actualArgs := append(append([]string{}, args...), "--format", format)
				exit, stdout, stderr := run(t, actualArgs)
				if exit != tc.exit {
					t.Fatalf("%s exit=%d want=%d stderr=%q", format, exit, tc.exit, stderr)
				}
				if exit == 2 {
					if len(stdout) != 0 || len(stderr) == 0 {
						t.Fatalf("invalid evidence emitted report: %q %q", stdout, stderr)
					}
					continue
				}
				if len(stderr) != 0 {
					t.Fatalf("valid report diagnosed an error: %q", stderr)
				}
				report, err := cvedelta.Compare(load(t, paths[0], paths[1]), load(t, paths[2], paths[3]), cvedelta.Options{FailOn: tc.failOn})
				if err != nil {
					t.Fatal(err)
				}
				var expected bytes.Buffer
				if format == "json" {
					err = cvedelta.WriteJSON(&expected, report)
					if actual := decode(t, stdout); !reflect.DeepEqual(actual, report) {
						t.Fatal("CLI JSON lost report fields")
					}
				} else {
					err = cvedelta.WriteMarkdown(&expected, report)
				}
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(stdout, expected.Bytes()) {
					t.Fatalf("%s CLI/library byte mismatch", format)
				}
				repeatedExit, repeated, repeatedErr := run(t, actualArgs)
				if repeatedExit != exit || !bytes.Equal(stdout, repeated) || len(repeatedErr) != 0 {
					t.Fatal("nondeterministic process result")
				}
				if bytes.Contains(stdout, []byte(root)) {
					t.Fatal("host path leaked into report")
				}
			}
			for path, snapshot := range snapshots {
				if !bytes.Equal(snapshot, read(t, path)) {
					t.Fatalf("input changed: %s", path)
				}
			}
		})
	}
}

func TestProcessInvalidInputsAndSelectors(t *testing.T) {
	var metadata map[string]any
	if err := json.Unmarshal(read(t, fixture("candidate.meta.json")), &metadata); err != nil {
		t.Fatal(err)
	}
	delete(metadata, "report_sha256")
	missingChecksum := filepath.Join(t.TempDir(), "missing.meta.json")
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(missingChecksum, data, 0o444); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{
		{"--candidate", filepath.Join(root, "testdata", "cli", "malformed.json")},
		{"--candidate-meta", missingChecksum},
		{"--candidate", filepath.Join(t.TempDir(), "missing\n\x1b[31m.json")},
		{"--format", "invalid"},
		{"--fail-on", "none,new"},
		{"--fail-on", "new,new"},
		{"--fail-on", "new,"},
		{"--fail-on", " new"},
		{"--fail-on", "unchanged"},
		{"--fail-on", ""},
		{"--bypass"},
		{"unexpected"},
	} {
		for _, format := range []string{"json", "markdown"} {
			// Invalid input/options must win even over database incomparability.
			base := append(defaults(), "--candidate-meta", fixture("database.meta.json"), "--format", format)
			exit, stdout, stderr := run(t, append(base, extra...))
			if exit != 2 || len(stdout) != 0 || len(stderr) == 0 {
				t.Fatalf("%q: exit=%d stdout=%q stderr=%q", extra, exit, stdout, stderr)
			}
			if strings.ContainsAny(strings.TrimSuffix(string(stderr), "\n"), "\n\r\x1b") || bytes.Contains(stderr, []byte("PRIVATE_BODY_DO_NOT_ECHO")) {
				t.Fatalf("unsafe diagnostic: %q", stderr)
			}
		}
	}
}

func TestProcessNoChangesCanStillBeIncomparable(t *testing.T) {
	before := load(t, fixture("baseline.json"), fixture("baseline.meta.json"))
	metadata := before.Metadata()
	metadata.Database.SHA256 = strings.Repeat("d", 64)
	path, meta := writeInput(t, t.TempDir(), "same-observations.json", before.Document(), metadata)
	args := append(compareArgs(fixture("baseline.json"), fixture("baseline.meta.json"), path, meta), "--fail-on=none", "--format=json")
	exit, stdout, stderr := run(t, args)
	if exit != 3 || len(stderr) != 0 {
		t.Fatalf("no-change database mismatch exit=%d stderr=%q", exit, stderr)
	}
	report := decode(t, stdout)
	if report.Decision != cvedelta.Incomparable || report.Comparable || report.Counts.Unchanged != len(report.Records) || len(report.Reasons) != 1 || report.Reasons[0].Code != cvedelta.DatabaseChanged {
		t.Fatal("unchanged observations hid incomparable provenance")
	}
}

func TestProcessDisappearanceAndChangedDatabase(t *testing.T) {
	args := append(defaults(), "--candidate-meta", fixture("database.meta.json"), "--fail-on=none")
	exit, stdout, stderr := run(t, append(args, "--format=json"))
	if exit != 3 || len(stderr) != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	report := decode(t, stdout)
	if report.Comparable || report.Decision != cvedelta.Incomparable || len(report.Reasons) != 1 || report.Reasons[0].Code != cvedelta.DatabaseChanged {
		t.Fatal("database provenance bypassed")
	}
	absences := map[string]cvedelta.AbsenceReason{}
	for _, row := range report.Records {
		if row.Category == cvedelta.NoLongerReported {
			if row.Before == nil || row.Before.Status != cvedelta.Patched || row.After != nil || row.AbsenceReason == nil {
				t.Fatal("disappearance context lost")
			}
			absences[row.Component.Name+"/"+row.CVEID] = *row.AbsenceReason
		}
	}
	if !reflect.DeepEqual(absences, map[string]cvedelta.AbsenceReason{
		"alpha/CVE-2099-0003": cvedelta.FindingAbsent, "gone/CVE-2099-0001": cvedelta.ComponentAbsent,
	}) {
		t.Fatalf("missing disappearance records: %+v", absences)
	}
	exit, stdout, stderr = run(t, args) // Omitted --format must mean Markdown.
	if exit != 3 || len(stderr) != 0 || !bytes.HasPrefix(stdout, []byte("# CVEDelta")) {
		t.Fatal("default Markdown outcome failed")
	}
	for _, text := range []string{"Comparable: false", "database_changed", "no_longer_reported", "component_absent", "finding_absent", "does not establish a fix"} {
		if !bytes.Contains(stdout, []byte(text)) {
			t.Fatalf("Markdown lost %s", text)
		}
	}
}

func writeInput(t *testing.T, directory, name string, document cvedelta.Document, metadata cvedelta.Metadata) (string, string) {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	metadata.ReportSHA256 = hex.EncodeToString(hash[:])
	meta, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	path, metaPath := filepath.Join(directory, name), filepath.Join(directory, name+".meta.json")
	if err := os.WriteFile(path, raw, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, meta, 0o444); err != nil {
		t.Fatal(err)
	}
	return path, metaPath
}

func TestProcessHostileContentAndPathsStayInert(t *testing.T) {
	directory := t.TempDir()
	before := load(t, fixture("baseline.json"), fixture("baseline.meta.json"))
	after := load(t, fixture("candidate.json"), fixture("candidate.meta.json"))
	text := "<script>alert('x')</script>|`[link](https://example.invalid)\n\x1b[31m $(touch exploited)"
	document := after.Document()
	document.Components[0].Name = text
	document.Components[0].Issues[0].Summary = &text
	document.Components[0].Issues[0].Link = &text
	path, metaPath := writeInput(t, directory, "candidate $(touch exploited) 'quoted'\n.json", document, after.Metadata())
	beforePath, beforeMeta := writeInput(t, directory, "baseline with spaces.json", before.Document(), before.Metadata())
	args := compareArgs(beforePath, beforeMeta, path, metaPath)
	for _, format := range []string{"json", "markdown"} {
		exit, stdout, stderr := run(t, append(args, "--format", format))
		if exit != 1 || len(stderr) != 0 {
			t.Fatalf("hostile input exit=%d stderr=%q", exit, stderr)
		}
		if format == "json" {
			found := false
			for _, row := range decode(t, stdout).Records {
				if row.After != nil && row.After.Attributes.Summary != nil && *row.After.Attributes.Summary == text {
					found = true
				}
			}
			if !found {
				t.Fatal("JSON lost exact hostile text")
			}
		} else if bytes.Contains(stdout, []byte("<script>")) || bytes.Contains(stdout, []byte{0x1b}) || bytes.Contains(stdout, []byte("\n\x1b[31m")) {
			t.Fatal("Markdown did not escape malicious content")
		}
		if bytes.Contains(stdout, []byte(directory)) {
			t.Fatal("report leaked input path")
		}
	}
	for _, marker := range []string{filepath.Join(root, "exploited"), filepath.Join(directory, "exploited")} {
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("input executed: %s (%v)", marker, err)
		}
	}
	for _, pair := range [][2]string{{path, metaPath}, {beforePath, beforeMeta}} {
		// ReadInput revalidates each raw checksum after all process invocations.
		load(t, pair[0], pair[1])
	}
}

func TestProcessBrokenStdoutExitsTwo(t *testing.T) {
	for _, extra := range [][]string{nil, {"--fail-on=none"}, {"--candidate-meta", fixture("database.meta.json")}} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		command := exec.CommandContext(ctx, binary, append(defaults(), extra...)...)
		command.Stdout = writer
		var stderr bytes.Buffer
		command.Stderr = &stderr
		err = command.Run()
		writer.Close()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(stderr.String(), "stdout") {
			t.Fatalf("broken stdout must exit2, including actual SIGPIPE behavior: %v, stderr=%q", err, stderr.String())
		}
	}
}
