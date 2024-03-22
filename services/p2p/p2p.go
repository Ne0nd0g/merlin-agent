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

// Package p2p is a service to process and return peer-to-peer connection links and delegate messages
package p2p

import (
	// Standard
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"syscall"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/p2p"
	"github.com/Ne0nd0g/merlin-agent/v2/p2p/memory"
)

// Service is the structure used to interact with Link and Delegate objects
type Service struct {
	repo p2p.Repository
}

// memoryService is an in-memory instantiation of the message service
var memoryService *Service

// out a global map of Delegate messages that are outgoing from this Agent to its parent or the server
var out = make(chan messages.Delegate, 100)

// NewP2PService is a factory to create a Service object for interacting with Link and Delegate message objects
func NewP2PService() *Service {
	if memoryService == nil {
		memoryService = &Service{
			repo: withP2PMemoryRepository(),
		}
	}
	return memoryService
}

// withP2PMemoryRepository creates and returns a repository for peer-to-peer links
func withP2PMemoryRepository() p2p.Repository {
	return memory.NewRepository()
}

// AddDelegate takes the provided delegate message and adds it to outgoing message channel to be sent to the Merlin server
func (s *Service) AddDelegate(delegate messages.Delegate) {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.AddDelegate(): entering into function with delegate message for %s, payload size: %d, delegate messages: %d", delegate.Agent, len(delegate.Payload), len(delegate.Delegates)))
	defer cli.Message(cli.DEBUG, "services/p2p.AddDelegate(): exiting function")
	out <- delegate
}

// AddLink stores a Link object in the repository
func (s *Service) AddLink(link *p2p.Link) {
	s.repo.Store(link)
}

// Connected determines if this Agent is already connected to the target IP address and port and returns it if it is
func (s *Service) Connected(agentType int, ip string) (*p2p.Link, bool) {
	links := s.repo.GetAll()
	for _, link := range links {
		if link.Type() == agentType && link.Remote().String() == ip {
			return link, true
		}
	}
	return nil, false
}

// Delete removes the peer-to-peer link from the repository without trying to gracefully close the connection
func (s *Service) Delete(id uuid.UUID) {
	s.repo.Delete(id)
}

// GetLink finds the Link by the provided id from the repository and returns it
func (s *Service) GetLink(id uuid.UUID) (*p2p.Link, error) {
	return s.repo.Get(id)
}

// GetDelegates blocks waiting for a delegate message that needs to be sent to the parent Agent
func (s *Service) GetDelegates() []messages.Delegate {
	delegate := <-out
	return []messages.Delegate{delegate}
}

// Check does not block and returns all delegate messages in the out channel, if any
func (s *Service) Check() (delegates []messages.Delegate) {
	for {
		if len(out) > 0 {
			delegate := <-out
			delegates = append(delegates, delegate)
		} else {
			break
		}
	}
	return
}

// Handle takes in a list of incoming Delegate messages to this parent Agent and sends it to the child or linked Agent
func (s *Service) Handle(delegates []messages.Delegate) {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): entering into function with %d delegate messages", len(delegates)))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): exiting function"))

	for _, delegate := range delegates {
		cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): processing delegate message for %s, payload size: %d, delegate messages: %d", delegate.Agent, len(delegate.Payload), len(delegate.Delegates)))
		link, err := s.repo.Get(delegate.Agent)
		if err != nil {
			cli.Message(cli.WARN, err.Error())
			continue
		}
		// Lock the link so other go routines don't try to write to it at the same time causing the child to receive packets out of order
		link.Lock()

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
		sleep := time.Millisecond * 30

		switch link.Type() {
		case p2p.SMBBIND, p2p.SMBREVERSE:
			// Split into fragments of MaxSize
			fragments := int(math.Ceil(float64(len(delegate.Payload)) / float64(p2p.MaxSizeSMB)))
			cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): SMB data size is: %d, max SMB fragment size is %d, creating %d fragments", len(delegate.Payload), p2p.MaxSizeSMB, fragments))
			var i int
			size := len(delegate.Payload)
			for i < fragments {
				start := i * p2p.MaxSizeSMB
				var stop int
				// if bytes remaining are less than max size, read until the end
				if size < p2p.MaxSizeSMB {
					stop = len(delegate.Payload)
				} else {
					stop = (i + 1) * p2p.MaxSizeSMB
				}
				n, err = link.Conn().(net.Conn).Write(delegate.Payload[start:stop])
				if err != nil {
					cli.Message(cli.WARN, fmt.Sprintf("services/p2p.Handle(): there was an error writing a message to the linked agent %s: %s\n", link.Conn().(net.Conn).RemoteAddr(), err))
					break
				}
				cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): Wrote SMB fragment %d of %d", i+1, fragments))
				i++
				size = size - p2p.MaxSizeSMB
			}
		case p2p.TCPBIND, p2p.TCPREVERSE:
			cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): Writing %d bytes to the linked agent %s at %s at %s\n", len(delegate.Payload), delegate.Agent, link.Remote(), time.Now().UTC().Format(time.RFC3339)))
			n, err = link.Conn().(net.Conn).Write(delegate.Payload)
			cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): Wrote %d bytes to the linked agent %s at %s at %s\n", n, delegate.Agent, link.Remote(), time.Now().UTC().Format(time.RFC3339)))
		case p2p.UDPBIND, p2p.UDPREVERSE:
			// Needed for space between consecutive delegate messages
			sleep = time.Second * 1
			// Split into fragments of MaxSize
			fragments := int(math.Ceil(float64(len(delegate.Payload)) / float64(p2p.MaxSizeUDP)))
			cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): UDP data size is: %d, max UDP fragment size is %d, creating %d fragments", len(delegate.Payload), p2p.MaxSizeUDP, fragments))
			var i int
			size := len(delegate.Payload)
			for i < fragments {
				start := i * p2p.MaxSizeUDP
				var stop int
				// if bytes remaining are less than max size, read until the end
				if size < p2p.MaxSizeUDP {
					stop = len(delegate.Payload)
				} else {
					stop = (i + 1) * p2p.MaxSizeUDP
				}
				switch link.Type() {
				case p2p.UDPBIND:
					n, err = link.Conn().(net.Conn).Write(delegate.Payload[start:stop])
				case p2p.UDPREVERSE:
					n, err = link.Conn().(net.PacketConn).WriteTo(delegate.Payload[start:stop], link.Remote())
				}
				if err != nil {
					cli.Message(cli.WARN, fmt.Sprintf("services/p2p.Handle(): there was an error writing a message to the linked agent %s: %s\n", link.Conn().(net.Conn).RemoteAddr(), err))
					break
				}
				cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Handle(): Wrote UDP fragment %d of %d", i+1, fragments))
				i++
				size = size - p2p.MaxSizeUDP
				// UDP packets seemed to get dropped if too many are sent too fast
				if fragments > 100 {
					time.Sleep(time.Millisecond * 10)
				}
			}
		default:
			cli.Message(cli.WARN, fmt.Sprintf("services/p2p.Handle(): unhandled Agent type: %d", link.Type()))
			break
		}

		if err != nil {
			if errors.Is(err, syscall.EPIPE) {
				cli.Message(cli.WARN, fmt.Sprintf("services/p2p.Handle(): the linked agent %s has closed the connection", link.Conn().(net.Conn).RemoteAddr()))
			} else if errors.Is(err, syscall.ECONNRESET) {
				cli.Message(cli.WARN, fmt.Sprintf("services/p2p.Handle(): the linked agent %s has reset the connection", link.Conn().(net.Conn).RemoteAddr()))
			} else if errors.Is(err, io.EOF) {
				cli.Message(cli.WARN, fmt.Sprintf("services/p2p.Handle(): the linked agent %s has closed the connection", link.Conn().(net.Conn).RemoteAddr()))
			} else {
				cli.Message(cli.WARN, fmt.Sprintf("services/p2p.Handle(): there was an error writing a message to the linked agent %s: %s\n", link.Conn().(net.Conn).RemoteAddr(), err))
			}
			cli.Message(cli.WARN, fmt.Sprintf("services/p2p.Handle(): removing the linked agent %s at %s from the repository", link.ID(), link.Conn().(net.Conn).RemoteAddr()))
			link.Unlock()
			s.Delete(link.ID())
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Wrote %d bytes to the linked agent %s at %s at %s\n", len(delegate.Payload), delegate.Agent, link.Remote(), time.Now().UTC().Format(time.RFC3339)))
		// Without a delay, synchronous connections can send multiple messages so fast that receiver thinks it is one message
		// TODO Fix this so that way an artificial sleep is not needed
		// Sent about 25 UDP IDLE messages in 1 second and caused the agent to receive them out of order
		time.Sleep(sleep)
		link.Unlock()
	}
}

// List returns a numbered list of peer-to-peer Links that exist each seperated by a new line
func (s *Service) List() (list string) {
	agents := s.repo.GetAll()
	list = fmt.Sprintf("Peer-to-Peer Links (%d)\n", len(agents))
	for i, agent := range agents {
		list += fmt.Sprintf("%d. %s:%s:%s\n", i, agent.String(), agent.ID(), agent.Remote())
	}
	return
}

// Refresh sends an empty delegate message to the server for each peer-to-peer Link in the repository to update the server
// with this Agent's links
func (s *Service) Refresh() (list string) {
	links := s.repo.GetAll()
	for _, link := range links {
		s.AddDelegate(messages.Delegate{
			Agent:    link.ID(),
			Listener: link.Listener(),
		})
	}
	return fmt.Sprintf("Created upstream delegate messages for:\n%s", s.List())
}

// Remove closes the peer-to-peer Link's network connection and deletes the peer-to-peer Link from the repository
func (s *Service) Remove(id uuid.UUID) error {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/p2p.Remove(): entering into function with id: %s", id))
	link, err := s.GetLink(id)
	if err != nil {
		return fmt.Errorf("services/p2p.Remove(): %s", err)
	}

	switch link.Type() {
	case p2p.TCPBIND, p2p.UDPBIND, p2p.SMBBIND:
		// Close the connection
		err = link.Conn().(net.Conn).Close()
		if err != nil {
			return fmt.Errorf("services/p2p.Remove(): there was an error closing the connection for link %s: %s", link.ID(), err)
		}
	default:
		return fmt.Errorf("services/p2p.Remove() unhandled peer-to-peer link type %d", link.Type())
	}
	s.repo.Delete(id)
	return nil
}

// UpdateConnection updates the peer-to-peer Link's network connection with the provided conn
func (s *Service) UpdateConnection(id uuid.UUID, conn interface{}, remote net.Addr) error {
	return s.repo.UpdateConn(id, conn, remote)
}
