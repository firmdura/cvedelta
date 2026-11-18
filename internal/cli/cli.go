// SPDX-License-Identifier: Apache-2.0

// Package cli implements the read-only command-line entrypoint. It returns exit
// codes to its caller and buffers a complete report before publishing stdout.
package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/firmdura/cvedelta/internal/decision"
	"github.com/firmdura/cvedelta/pkg/cvedelta"
)

const version = "v1.0.1"

// Run executes arguments excluding argv[0]. Diagnostics go only to stderr;
// version information and valid reports go only to stdout, including report
// outcomes 1 and 3. Errors take precedence over all decisions and return 2.
// A failed stdout write can leave bytes already written, but
// parsing/comparison/rendering failures emit none.
func Run(args []string, stdout, stderr io.Writer) int {
	data, outcome, err := commandOutput(args)
	if err == nil {
		if stdout == nil {
			err = errors.New("stdout: nil writer")
		} else {
			var n int
			n, err = stdout.Write(data)
			if err == nil && n != len(data) {
				err = io.ErrShortWrite
			}
			if err != nil {
				err = fmt.Errorf("stdout: %w", err)
			}
		}
	}
	if err != nil && stderr != nil {
		// Flags, paths and OS errors can contain arbitrary controls/newlines.
		// Quote the entire diagnostic instead of permitting terminal injection.
		fmt.Fprintln(stderr, "cvedelta:", strconv.QuoteToASCII(err.Error()))
	}
	return decision.ExitCode(outcome, err)
}

func commandOutput(args []string) ([]byte, cvedelta.Decision, error) {
	if len(args) == 1 && args[0] == "--version" {
		return []byte("cvedelta " + version + "\n"), cvedelta.Clean, nil
	}
	if len(args) == 0 || args[0] != "compare" {
		return nil, "", errors.New("expected command: compare")
	}
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	// The flag package's default diagnostics echo arbitrary argument text.
	flags.SetOutput(io.Discard)
	baseline := flags.String("baseline", "", "baseline report path (required)")
	baselineMeta := flags.String("baseline-meta", "", "baseline metadata path (required)")
	candidate := flags.String("candidate", "", "candidate report path (required)")
	candidateMeta := flags.String("candidate-meta", "", "candidate metadata path (required)")
	format := flags.String("format", "markdown", "json or markdown")
	failOn := flags.String("fail-on", "", "comma-separated changed categories, or none")
	if err := flags.Parse(args[1:]); err != nil {
		return nil, "", err
	}
	if flags.NArg() != 0 {
		return nil, "", errors.New("compare: unexpected positional arguments")
	}
	for _, required := range []struct{ name, value string }{
		{"baseline", *baseline}, {"baseline-meta", *baselineMeta},
		{"candidate", *candidate}, {"candidate-meta", *candidateMeta},
	} {
		if required.value == "" {
			return nil, "", fmt.Errorf("compare: --%s is required", required.name)
		}
	}
	if *format != "json" && *format != "markdown" {
		return nil, "", errors.New("compare: --format must be json or markdown")
	}
	options := cvedelta.Options{}
	var err error
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "fail-on" {
			options, err = decision.ParseFailOn(*failOn)
		}
	})
	if err != nil {
		return nil, "", err
	}
	before, err := readInput(*baseline, *baselineMeta)
	if err != nil {
		return nil, "", fmt.Errorf("baseline input: %w", err)
	}
	after, err := readInput(*candidate, *candidateMeta)
	if err != nil {
		return nil, "", fmt.Errorf("candidate input: %w", err)
	}
	report, err := cvedelta.Compare(before, after, options)
	if err != nil {
		return nil, "", err
	}
	var output bytes.Buffer
	if *format == "json" {
		err = cvedelta.WriteJSON(&output, report)
	} else {
		err = cvedelta.WriteMarkdown(&output, report)
	}
	if err != nil {
		return nil, "", err
	}
	return output.Bytes(), report.Decision, nil
}

func readInput(reportPath, metadataPath string) (cvedelta.Input, error) {
	report, err := os.Open(reportPath)
	if err != nil {
		return cvedelta.Input{}, err
	}
	metadata, err := os.Open(metadataPath)
	if err != nil {
		return cvedelta.Input{}, errors.Join(err, report.Close())
	}
	input, readErr := cvedelta.ReadInput(report, metadata)
	err = errors.Join(readErr, report.Close(), metadata.Close())
	if err != nil {
		return cvedelta.Input{}, err
	}
	return input, nil
}
