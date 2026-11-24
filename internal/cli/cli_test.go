// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firmdura/cvedelta/internal/cli"
)

func args() []string {
	fixture := filepath.Join("..", "..", "testdata", "provenance", "synthetic")
	return []string{"compare", "--baseline", filepath.Join(fixture, "baseline.json"),
		"--baseline-meta", filepath.Join(fixture, "baseline.meta.json"),
		"--candidate", filepath.Join(fixture, "candidate.json"),
		"--candidate-meta", filepath.Join(fixture, "candidate.meta.json")}
}

func TestOfflineHelp(t *testing.T) {
	for _, argv := range [][]string{{"-h"}, {"--help"}, {"compare", "-h"}, {"compare", "--help"}} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if exit := cli.Run(argv, &stdout, &stderr); exit != 0 || stderr.Len() != 0 {
				t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
			}
			for _, want := range []string{"Usage:", "cvedelta compare", "--baseline ", "--baseline-meta ", "--candidate ", "--candidate-meta ", "--format", "--fail-on", "incomparable"} {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("help is missing %q", want)
				}
			}
		})
	}
}

func TestStrictArgumentsEmitNoReport(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing command", nil},
		{"unknown command", []string{"other"}},
		{"version with extra argument", []string{"--version", "extra"}},
		{"version with unknown flag", []string{"--version", "--unknown"}},
		{"help with extra argument", []string{"--help", "extra"}},
		{"help before compare arguments", []string{"compare", "-h", "--format=json"}},
		{"help after compare arguments", append(args(), "--help")},
		{"missing required", []string{"compare"}},
		{"empty required", append(args(), "--baseline=")},
		{"unknown flag", append(args(), "--bypass")},
		{"version is not a compare flag", append(args(), "--version")},
		{"extra positional", append(args(), "extra")},
		{"wrong format", append(args(), "--format=JSON")},
		{"empty selector", append(args(), "--fail-on=")},
		{"empty token", append(args(), "--fail-on=new,")},
		{"spaces", append(args(), "--fail-on=new, status_changed")},
		{"unknown category", append(args(), "--fail-on=fixed")},
		{"unchanged category", append(args(), "--fail-on=unchanged")},
		{"duplicates", append(args(), "--fail-on=new,new")},
		{"mixed none", append(args(), "--fail-on=none,new")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if exit := cli.Run(tc.args, &stdout, &stderr); exit != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
			}
		})
	}
}

type failingWriter struct{ partial bool }

func (w failingWriter) Write(p []byte) (int, error) {
	if w.partial {
		return len(p) / 2, errors.New("output failed")
	}
	return 0, nil
}

func TestOutputErrorsOverrideDecision(t *testing.T) {
	for _, commandArgs := range [][]string{
		args(),
		append(args(), "--fail-on=none"),
		append(args(), "--candidate-meta=../../testdata/provenance/synthetic/database.meta.json"),
		{"--version"},
		{"compare", "--help"},
	} {
		for _, writer := range []io.Writer{nil, failingWriter{}, failingWriter{true}} {
			var stderr bytes.Buffer
			if exit := cli.Run(commandArgs, writer, &stderr); exit != 2 || !strings.Contains(stderr.String(), "stdout") {
				t.Fatalf("output error did not override report decision: exit=%d, stderr=%q", exit, stderr.String())
			}
		}
	}
}

func TestDiagnosticControlsAreEscaped(t *testing.T) {
	for _, badArgs := range [][]string{
		append(args(), "--baseline=missing\n\x1b[31m\u202e.json"),
		append(args(), "--unknown\n\x1b[31m"),
		append(args(), "--fail-on=new,\n\x1b[31m"),
	} {
		var stdout, stderr bytes.Buffer
		if cli.Run(badArgs, &stdout, &stderr) != 2 || stdout.Len() != 0 {
			t.Fatal("expected input error")
		}
		if strings.ContainsAny(strings.TrimSuffix(stderr.String(), "\n"), "\n\r\x1b\u202e") {
			t.Fatalf("terminal controls leaked: %q", stderr.String())
		}
	}
}
