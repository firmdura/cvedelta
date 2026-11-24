// SPDX-License-Identifier: Apache-2.0

// Delivery checks use the public facade and the real built CLI only.
package acceptance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/firmdura/cvedelta/pkg/cvedelta"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestDelivery(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	// Ordinary unit/race verification runs this package too, building into dist.
	// make acceptance supplies its separately built binary explicitly.
	binary := os.Getenv("CVEDELTA_BINARY")
	if binary == "" {
		binary = filepath.Join(root, "dist", "acceptance-test", "cvedelta")
		if err := os.MkdirAll(filepath.Dir(binary), 0755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-buildvcs=false", "-trimpath", "-o", binary, "./cmd/cvedelta")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v: %s", err, out)
		}
	}
	read := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// Snapshot all delivered example and fixture files, not just current inputs.
	snapshot := map[string][]byte{}
	for _, dir := range []string{"testdata", "examples"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				snapshot[path] = b
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for path, before := range snapshot {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Errorf("input changed: %s (%v)", path, err)
			}
		}
	})
	// Local resources prevent schema validation from making network requests.
	schemaCompiler := jsonschema.NewCompiler()
	schemaCompiler.LoadURL = func(url string) (io.ReadCloser, error) { return nil, fmt.Errorf("unregistered schema: %s", url) }
	for _, name := range []string{"metadata-v1.schema.json", "report-v1.schema.json", "yocto-v1.schema.json"} {
		if err := schemaCompiler.AddResource("https://cvedelta.invalid/"+name, bytes.NewReader(read("schemas/"+name))); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := schemaCompiler.Compile("https://cvedelta.invalid/report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	const s = "testdata/provenance/synthetic/"
	const q = "examples/quickstart/"
	const p = "testdata/provenance/producer/"
	type scenario struct {
		name, b, bm, c, cm, fail, golden string
		status                           int
	}
	cases := []scenario{
		{"synthetic", s + "baseline.json", s + "baseline.meta.json", s + "candidate.json", s + "candidate.meta.json", "", "report-changes", 1},
		{"none", s + "baseline.json", s + "baseline.meta.json", s + "candidate.json", s + "candidate.meta.json", "none", "report-none", 0},
		{"database-none", s + "baseline.json", s + "baseline.meta.json", s + "candidate.json", s + "database.meta.json", "none", "", 3},
		{"all-reasons", s + "baseline.json", s + "baseline-incomplete.meta.json", s + "candidate.json", s + "all-incomparable.meta.json", "none", "report-incomparable", 3},
		{"identical", s + "baseline.json", s + "baseline.meta.json", s + "baseline.json", s + "baseline.meta.json", "", "report-unchanged", 0},
		{"incomplete-identical", s + "baseline.json", s + "baseline-incomplete.meta.json", s + "baseline.json", s + "baseline-incomplete.meta.json", "none", "", 3},
		{"malformed", s + "baseline.json", s + "baseline.meta.json", "testdata/cli/malformed.json", s + "database.meta.json", "none", "", 2},
		{"checksum", s + "baseline.json", s + "baseline.meta.json", s + "candidate.json", s + "wrong-checksum.meta.json", "none", "", 2},
		{"configuration", s + "baseline.json", s + "baseline.meta.json", s + "candidate.json", s + "configuration-mismatch.meta.json", "none", "", 2},
		{"invalid-policy", s + "baseline.json", s + "baseline.meta.json", s + "candidate.json", s + "database.meta.json", "unchanged", "", 2},
		{"producer", p + "report.json", p + "report.meta.json", p + "report.json", p + "report.meta.json", "", "", 0},
		{"quickstart", q + "baseline.json", q + "baseline.meta.json", q + "candidate.json", q + "candidate.meta.json", "", "", 1},
		{"quickstart-database", q + "baseline.json", q + "baseline.meta.json", q + "candidate.json", q + "candidate-database.meta.json", "none", "", 3},
	}
	invoke := func(program string, args ...string) ([]byte, []byte, int) {
		t.Helper()
		cmd := exec.Command(program, args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CVEDELTA_BINARY="+binary)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		status := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				status = e.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return stdout.Bytes(), stderr.Bytes(), status
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, format := range []string{"json", "markdown"} {
				args := []string{"compare", "--baseline", c.b, "--baseline-meta", c.bm, "--candidate", c.c, "--candidate-meta", c.cm, "--format", format}
				if c.fail != "" {
					args = append(args, "--fail-on", c.fail)
				}
				stdout, stderr, status := invoke(binary, args...)
				if status != c.status {
					t.Fatalf("%s exit %d, want %d: %s", format, status, c.status, stderr)
				}
				if status == 2 {
					if len(stdout) != 0 || len(stderr) == 0 {
						t.Fatalf("error must have empty stdout and diagnostic stderr")
					}
					continue
				}
				if len(stderr) != 0 {
					t.Fatalf("unexpected stderr: %s", stderr)
				}
				again, againErr, againStatus := invoke(binary, args...)
				if againStatus != status || !bytes.Equal(stdout, again) || len(againErr) != 0 {
					t.Fatal("nondeterministic output")
				}
				b, err := cvedelta.ReadInput(bytes.NewReader(read(c.b)), bytes.NewReader(read(c.bm)))
				if err != nil {
					t.Fatal(err)
				}
				candidate, err := cvedelta.ReadInput(bytes.NewReader(read(c.c)), bytes.NewReader(read(c.cm)))
				if err != nil {
					t.Fatal(err)
				}
				opts := cvedelta.Options{}
				if c.fail == "none" {
					opts.FailOn = []cvedelta.Category{}
				}
				report, err := cvedelta.Compare(b, candidate, opts)
				if err != nil {
					t.Fatal(err)
				}
				var library bytes.Buffer
				if format == "json" {
					err = cvedelta.WriteJSON(&library, report)
					var value any
					if err := json.Unmarshal(stdout, &value); err != nil {
						t.Fatal(err)
					}
					if err := schema.Validate(value); err != nil {
						t.Fatal(err)
					}
					var decoded cvedelta.Report
					if err := json.Unmarshal(stdout, &decoded); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(decoded, report) {
						t.Fatal("JSON lost report fields")
					}
					if c.name == "synthetic" && (report.Counts != (cvedelta.Counts{New: 2, NoLongerReported: 2, StatusChanged: 1, ContextChanged: 2, Unchanged: 3}) || len(report.Records) != 10 || len(report.ComponentVersionChanges) != 2) {
						t.Fatal("incomplete synthetic observations")
					}
					if c.name == "quickstart" && report.Counts != (cvedelta.Counts{New: 1, NoLongerReported: 1, StatusChanged: 1}) {
						t.Fatal("quickstart categories missing")
					}
				} else {
					err = cvedelta.WriteMarkdown(&library, report)
				}
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(stdout, library.Bytes()) {
					t.Fatalf("%s CLI/library byte mismatch", format)
				}
				if c.golden != "" {
					ext := ".json"
					if format == "markdown" {
						ext = ".md"
					}
					if !bytes.Equal(stdout, read("testdata/render/"+c.golden+ext)) {
						t.Fatalf("%s differs from independent golden", format)
					}
				}
			}
		})
	}
	// Exercise the exact CI wrapper's four branches without losing the status.
	for _, index := range []int{6, 0, 1, 2} {
		c := cases[index]
		args := []string{"examples/ci.sh", "--baseline", c.b, "--baseline-meta", c.bm, "--candidate", c.c, "--candidate-meta", c.cm, "--format", "json"}
		if c.fail != "" {
			args = append(args, "--fail-on", c.fail)
		}
		_, stderr, status := invoke("sh", args...)
		if status != c.status || len(stderr) == 0 {
			t.Fatalf("CI branch %s: %d: %s", c.name, status, stderr)
		}
	}
	// Help is not a comparison decision and must not replace the last report.
	saved := read("dist/ci/report.json")
	if !json.Valid(saved) {
		t.Fatal("expected a saved JSON comparison report")
	}
	for _, flag := range []string{"--help", "-h"} {
		out, stderr, status := invoke("sh", "examples/ci.sh", flag)
		if status != 0 || len(stderr) != 0 || !bytes.Contains(out, []byte("cvedelta compare")) {
			t.Fatalf("CI %s: exit=%d stdout=%q stderr=%q", flag, status, out, stderr)
		}
		if !bytes.Equal(saved, read("dist/ci/report.json")) {
			t.Fatalf("CI %s replaced the comparison report", flag)
		}
	}
	// Literally exercise canonicalization and metadata generation on repo files.
	policy, stderr, status := invoke("python3", "examples/provenance.py", "coverage", q+"coverage-source.json")
	if status != 0 || !bytes.Equal(policy, read(q+"coverage-policy.json")) {
		t.Fatalf("coverage example: %d: %s", status, stderr)
	}
	for _, side := range []string{"baseline", "candidate"} {
		build, revision := "demo-before", "original-synthetic-before"
		if side == "candidate" {
			build, revision = "demo-after", "original-synthetic-after"
		}
		out, stderr, status := invoke("python3", "examples/provenance.py", "metadata", "--report", q+side+".json", "--database", q+"database.json", "--coverage", q+"coverage-policy.json", "--configuration-id", "demo:demo-machine:demo-distro:demo-image", "--build-id", build, "--source-revision", revision, "--scanner-revision", "original-synthetic-producer-v1", "--complete", "true")
		if status != 0 || !bytes.Equal(out, read(q+side+".meta.json")) {
			t.Fatalf("metadata example: %d: %s", status, stderr)
		}
	}
}
