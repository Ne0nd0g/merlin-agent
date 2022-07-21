//go:build !windows
// +build !windows

package commands

import (
	// Standard
	"fmt"

	// Merlin Main
	"github.com/Ne0nd0g/merlin/pkg/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
)

// CLR is the entrypoint for Jobs that are processed to determine which CLR function should be executed
func CLR(cmd jobs.Command) jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering CLR() with %+v", cmd))
	return jobs.Results{
		Stderr: "the CLR module is not supported by this agent type",
	}
}
