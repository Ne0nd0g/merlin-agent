// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2023  Russel Van Tuyl

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
	"bytes"
	"encoding/base64"
	"encoding/binary"
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
	p2pService "github.com/Ne0nd0g/merlin-agent/services/p2p"
)

// peerToPeerService is used to work with peer-to-peer Agent connections/link to include handling or getting Delegate messages
var peerToPeerService *p2pService.Service

func init() {
	peerToPeerService = p2pService.NewP2PService()
}

// Link connects to the provided target over the provided protocol and establishes a peer-to-peer connection with the Agent
func Link(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/link.Link(): entering into function with %+v", cmd))

	if len(cmd.Args) < 1 {
		return jobs.Results{Stderr: fmt.Sprintf("expected 1 argument with the link command, received %d: %+v", len(cmd.Args), cmd.Args)}
	}

	// switch on first argument
	switch strings.ToLower(cmd.Args[0]) {
	case "list":
		results.Stdout = peerToPeerService.List()
		return
	case "tcp":
		if len(cmd.Args) < 2 {
			return jobs.Results{Stderr: fmt.Sprintf("expected 2 arguments with the link tcp command, received %d: %+v", len(cmd.Args), cmd.Args)}
		}
		return Connect("tcp", cmd.Args[1:])
	case "udp":
		if len(cmd.Args) < 2 {
			return jobs.Results{Stderr: fmt.Sprintf("expected 2 arguments with the link udp command, received %d: %+v", len(cmd.Args), cmd.Args)}
		}
		return Connect("udp", cmd.Args[1:])
	case "smb":
		if len(cmd.Args) < 3 {
			return jobs.Results{Stderr: fmt.Sprintf("expected 2 arguments with the link smb command, received %d: %+v\n Example: link smb 192.168.1.1 merlinPipe", len(cmd.Args), cmd.Args)}
		}
		return ConnectSMB(cmd.Args[1], cmd.Args[2])
	default:
		return jobs.Results{
			Stderr: fmt.Sprintf("Unhandled link type: %s", cmd.Args[0]),
		}
	}
}

// Connect establishes a TCP or UDP connection to a tcp-bind or udp-bind peer-to-peer Agent
func Connect(network string, args []string) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/link.Connect(): entering into function with network: %s, args: %+v", network, args))

	var linkType int
	switch strings.ToLower(network) {
	case "tcp":
		linkType = p2p.TCPBIND
	case "udp":
		linkType = p2p.UDPBIND
	}

	// args[0] = target (e.g., 192.168.1.10:8080)
	if len(args) <= 0 {
		results.Stderr = fmt.Sprintf("Expected 1 argument, received %d", len(args))
		return
	}

	// See if there is already a link or connection to the target IP & Port
	link, ok := peerToPeerService.Connected(linkType, args[0])
	if ok {
		results.Stderr = fmt.Sprintf("already connected to %s: %s:%s\n", link.Remote(), link.String(), link.ID())
		return
	}

	var err error
	var conn net.Conn

	// Establish connection to downstream agent
	switch linkType {
	case p2p.TCPBIND, p2p.UDPBIND:
		conn, err = net.Dial(network, args[0])
	default:
		err = fmt.Errorf("unhandled linked Agent type: %d", linkType)
	}

	if err != nil {
		results.Stderr = fmt.Sprintf("commands/link.Connect(): there was an error attempting to link the agent: %s", err.Error())
		return
	}

	var n int

	// We must first write data to the UDP connection to let the UDP bind Agent know we're listening and ready
	if linkType == p2p.UDPBIND {
		junk := core.RandStringBytesMaskImprSrc(rand.Intn(100))
		junk = base64.StdEncoding.EncodeToString([]byte(junk))
		cli.Message(cli.NOTE, fmt.Sprintf("Initiating UDP connection to %s sending junk data: %s", conn.RemoteAddr(), junk))
		n, err = conn.Write([]byte(junk))
		cli.Message(cli.NOTE, fmt.Sprintf("Wrote %d bytes to UDP connection from %s at %s", n, conn.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error writing data to the UDP connection: %s", err)
			return
		}
		// Wait for linked agent first checking message
		cli.Message(cli.NOTE, fmt.Sprintf("Waiting to recieve UDP connection from %s at %s...", conn.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))
	}

	var tag uint32
	var length uint64
	var buff bytes.Buffer
	for {
		data := make([]byte, 4096)
		// Need to have a read on the network connection for data here in this function to retrieve the linked Agent's ID so the linkedAgent structure can be stored
		n, err = conn.Read(data)
		if err != nil {
			msg := fmt.Sprintf("there was an error reading data from linked agent %s: %s", args[0], err)
			results.Stderr = msg
			cli.Message(cli.WARN, msg)
			return
		}
		cli.Message(cli.DEBUG, fmt.Sprintf("commands/link.Connect(): Read %d bytes from linked %s agent %s at %s", n, p2p.String(linkType), args[0], time.Now().UTC().Format(time.RFC3339)))

		// Add the bytes to the buffer
		n, err = buff.Write(data[:n])
		if err != nil {
			msg := fmt.Sprintf("commands/link.Connect(): there was an error writing %d bytes from linked agent into the buffer %s: %s", n, args[0], err)
			results.Stderr = msg
			cli.Message(cli.WARN, msg)
			return
		}

		// If this is the first read on the connection determine the tag and data length
		if tag == 0 {
			// Ensure we have enough data to read the tag/type which is 4-bytes
			if buff.Len() < 4 {
				cli.Message(cli.DEBUG, fmt.Sprintf("commands/link.Connect(): Need at least 4 bytes in the buffer to read the Type/Tag for TLV but only have %d", buff.Len()))
				continue
			}
			tag = binary.BigEndian.Uint32(data[:4])
			if tag != 1 {
				msg := fmt.Sprintf("commands/link.Connect(): Expected a type/tag value of 1 for TLV but got %d", tag)
				results.Stderr = msg
				cli.Message(cli.WARN, msg)
				return
			}
		}

		if length == 0 {
			// Ensure we have enough data to read the Length from TLV which is 8-bytes plus the 4-byte tag/type size
			if buff.Len() < 12 {
				cli.Message(cli.DEBUG, fmt.Sprintf("command/link.Connect(): Need at least 12 bytes in the buffer to read the Length for TLV but only have %d", buff.Len()))
				continue
			}
			length = binary.BigEndian.Uint64(data[4:12])
		}

		// If we've read all the data according to the length provided in TLV, then break the for loop
		// Type/Tag size is 4-bytes, Length size is 8-bytes for TLV
		if uint64(buff.Len()) == length+4+8 {
			cli.Message(cli.DEBUG, fmt.Sprintf("command/link.Connect(): Finished reading data length of %d bytes into the buffer and moving forward to deconstruct the data", length))
			break
		} else {
			cli.Message(cli.DEBUG, fmt.Sprintf("command/link.Connect(): Read %d of %d bytes into the buffer", buff.Len(), length+4+8))
		}
	}
	cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from linked %s agent %s at %s", buff.Len(), p2p.String(linkType), args[0], time.Now().UTC().Format(time.RFC3339)))

	// Decode GOB from server response into Base
	var msg messages.Delegate
	// First 4-bytes are for the Type/Tag, next 8-bytes are for the Length in TLV
	reader := bytes.NewReader(buff.Bytes()[12:])

	errD := gob.NewDecoder(reader).Decode(&msg)
	if errD != nil {
		err = fmt.Errorf("there was an error decoding the gob message:\r\n%s", errD.Error())
		return
	}

	// Store LinkedAgent
	linkedAgent := p2p.NewLink(msg.Agent, conn, linkType, conn.RemoteAddr())
	peerToPeerService.AddLink(linkedAgent)

	peerToPeerService.AddDelegate(msg)

	results.Stdout = fmt.Sprintf("Successfully connected to %s at %s", msg.Agent, args[0])

	// The listen function is in commands/listen.go
	go listen(conn, linkType)
	return
}
