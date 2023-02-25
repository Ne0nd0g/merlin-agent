package commands

import (
	// Standard
	"fmt"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
)

// Unlink terminates a peer-to-peer Agent connection
func Unlink(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/unlink.Unlink(): entering into function with %+v", cmd))

	if len(cmd.Args) < 1 {
		return jobs.Results{Stderr: fmt.Sprintf("expected 1 arguments with the link command, received %d: %+v", len(cmd.Args), cmd.Args)}
	}

	// Convert Agent ID to UUID
	agentID, err := uuid.FromString(cmd.Args[0])
	if err != nil {
		results.Stderr = fmt.Sprintf("commands/unlink.Unlink(): there was an error converting Agent ID %s to a valid UUID: %s", cmd.Args[0], err)
		return
	}

	// Remove the link
	err = peerToPeerService.Remove(agentID)
	if err != nil {
		results.Stderr += fmt.Sprintf("commands/unlink.Unlink(): there was an error removing the link for %s: %s", agentID, err)
	} else {
		results.Stdout = fmt.Sprintf("Successfully unlinked from %s and closed the network connection", agentID)
	}

	return
}
