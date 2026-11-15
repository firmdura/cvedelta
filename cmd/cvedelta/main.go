// SPDX-License-Identifier: Apache-2.0

// Command cvedelta compares two explicitly supplied Yocto cve-check reports.
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/firmdura/cvedelta/internal/cli"
)

func main() {
	// Go otherwise terminates the process on an EPIPE from stdout/stderr.
	// Let stdout.Write return its error so the CLI can honor exit precedence 2.
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
