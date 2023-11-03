package commands

import (
	// Standard
	"encoding/base64"
	"fmt"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// Unlink terminates a peer-to-peer Agent connection
func Unlink(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/unlink.Unlink(): entering into function with %+v", cmd))

	if len(cmd.Args) < 1 {
		return jobs.Results{Stderr: fmt.Sprintf("expected 1 arguments with the link command, received %d: %+v", len(cmd.Args), cmd.Args)}
	}

	// Convert Agent ID to UUID
	agentID, err := uuid.Parse(cmd.Args[0])
	if err != nil {
		results.Stderr = fmt.Sprintf("commands/unlink.Unlink(): there was an error converting Agent ID %s to a valid UUID: %s", cmd.Args[0], err)
		return
	}

	link, err := peerToPeerService.GetLink(agentID)
	if err != nil {
		results.Stderr = fmt.Sprintf("commands/unlink.Unlink(): there was an error getting the link for %s: %s", cmd.Args[0], err)
		return
	}

	// If there is a second argument, it contains a final message to send to the child agent before unlinking
	if len(cmd.Args) > 1 {
		delegate := messages.Delegate{
			Agent: agentID,
		}
		// Base64 decode the message
		delegate.Payload, err = base64.StdEncoding.DecodeString(cmd.Args[1])
		if err != nil {
			results.Stderr = fmt.Sprintf("commands/unlink.Unlink(): there was an error base64 decoding the embedded messagek, (%d) bytes, for %s: %s", len(cmd.Args[1]), agentID, err)
			return
		}
		// Send the message to the child agent
		cli.Message(cli.NOTE, fmt.Sprintf("Sending final message to child agent %s before removing peer-to-peer link at %s", agentID, time.Now().UTC().Format(time.RFC3339)))
		peerToPeerService.Handle([]messages.Delegate{delegate})
	}

	// Remove the link
	err = peerToPeerService.Remove(agentID)
	if err != nil {
		results.Stderr += fmt.Sprintf("commands/unlink.Unlink(): there was an error removing the link for %s: %s", agentID, err)
	} else {
		results.Stdout = fmt.Sprintf("Successfully unlinked from %s Agent %s and closed the network connection", link.String(), agentID)
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("commands/unlink.Unlink(): leaving the function with %+v", results))
	return
}
