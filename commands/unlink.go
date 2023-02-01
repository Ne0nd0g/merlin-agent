package commands

import (
	// Standard
	"fmt"
	"net"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin-agent/p2p"
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

	// Find connection
	agent, ok := p2p.LinkedAgents.Load(agentID)
	if !ok {
		results.Stderr = fmt.Sprintf("commands/unlink.Unlink(): unable to find Agent %s in the peer-to-peer Agent map", agentID)
		return
	}

	switch agent.(p2p.Agent).Type {
	case p2p.TCPBIND, p2p.UDPBIND:
		// Close the connection
		err = agent.(p2p.Agent).Conn.(net.Conn).Close()
		if err != nil {
			results.Stderr += fmt.Sprintf("commands/unlink.Unlink(): there was an error closing the network connection for %s: %s", agentID, err)
			return
		}
		results.Stdout = fmt.Sprintf("Successfully unlinked from %s and closed the network connection", agentID)
	default:
		results.Stderr = fmt.Sprintf("commands/unlink.Unlink(): unhandled peer-to-peer Agent connection type %d", agent.(p2p.Agent).Type)
		return
	}

	// Delete connection
	p2p.LinkedAgents.Delete(agentID)

	return
}
