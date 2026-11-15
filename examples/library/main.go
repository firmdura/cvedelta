// SPDX-License-Identifier: Apache-2.0

// A small application using only CVEDelta's public API. Run from the repo root.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/firmdura/cvedelta/pkg/cvedelta"
)

func read(reportPath, metadataPath string) (cvedelta.Input, error) {
	r, err := os.Open(reportPath)
	if err != nil {
		return cvedelta.Input{}, err
	}
	defer r.Close()
	m, err := os.Open(metadataPath)
	if err != nil {
		return cvedelta.Input{}, err
	}
	defer m.Close()
	return cvedelta.ReadInput(r, m)
}

func run() error {
	baseline := flag.String("baseline", "examples/quickstart/baseline.json", "report path")
	baselineMeta := flag.String("baseline-meta", "examples/quickstart/baseline.meta.json", "metadata path")
	candidate := flag.String("candidate", "examples/quickstart/candidate.json", "report path")
	candidateMeta := flag.String("candidate-meta", "examples/quickstart/candidate.meta.json", "metadata path")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional argument")
	}
	b, err := read(*baseline, *baselineMeta)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	c, err := read(*candidate, *candidateMeta)
	if err != nil {
		return fmt.Errorf("candidate: %w", err)
	}
	report, err := cvedelta.Compare(b, c, cvedelta.Options{})
	if err != nil {
		return err
	}
	// All three valid decisions carry useful output. This application writes it
	// and returns success; a CI adapter should branch on report.Decision.
	return cvedelta.WriteJSON(os.Stdout, report)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
