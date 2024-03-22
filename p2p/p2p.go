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

// Package p2p is used for Agent based peer-to-peer communications
package p2p

import (
	// Standard
	"fmt"
	"net"
	"sync"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"
)

// Types of peer-to-peer links/connections
const (
	TCPBIND    = 0
	TCPREVERSE = 1
	UDPBIND    = 2
	UDPREVERSE = 3
	SMBBIND    = 4
	SMBREVERSE = 5
)

const (
	// MaxSizeUDP is the maximum size of a UDP fragment
	// http://ithare.com/udp-from-mog-perspective/
	MaxSizeUDP = 1450
	// MaxSizeSMB is the maximum size of an SMB fragment
	// The WriteFileEx Windows API function says:
	// "Pipe write operations across a network are limited to 65,535 bytes per write"
	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefileex
	MaxSizeSMB = 65535
)

// Link holds information about peer-to-peer linked agents
type Link struct {
	id         uuid.UUID          // id is Agent id for this peer-to-peer connection
	in         chan messages.Base // in a channel of incoming Base messages coming in from the linked Agent
	out        chan messages.Base // out a channel of outgoing Base messages to be sent to the linked Agent
	conn       interface{}        // conn the network connection used to communicate with the linked Agent
	connType   int                // connType of the linked Agent (e.g., tcp-bind, SMB, etc.)
	remote     net.Addr           // remote is the name or address of the remote Agent data is being sent to
	listener   uuid.UUID          // listener is the server-side listener id for this link
	sync.Mutex                    // Mutex is used to lock the Link object for thread safety
}

// NewLink is a factory to build and return a Link structure
func NewLink(id uuid.UUID, listener uuid.UUID, conn interface{}, linkType int, remote net.Addr) *Link {
	return &Link{
		id:       id,
		in:       make(chan messages.Base, 100),
		out:      make(chan messages.Base, 100),
		conn:     conn,
		connType: linkType,
		remote:   remote,
		listener: listener,
	}
}

// AddIn takes in a base message from a parent Agent or the Merlin server and adds it to the incoming message channel,
// so it can be sent to the child Agent
func (l *Link) AddIn(base messages.Base) {
	l.in <- base
}

// AddOut takes in a base message from a child Agent and adds it to the outgoing message channel, so it can be sent to
// the Merlin server
func (l *Link) AddOut(base messages.Base) {
	l.out <- base
}

// Conn returns the peer-to-peer network connection used to read and write network traffic
func (l *Link) Conn() interface{} {
	return l.conn
}

// GetIn blocks waiting for a Base message from the incoming message channel and returns it
func (l *Link) GetIn() messages.Base {
	return <-l.in
}

// GetOut blocks waiting for a Base message from the outgoing message channel and returns it
func (l *Link) GetOut() messages.Base {
	return <-l.out
}

// ID returns the peer-to-peer Link's id
func (l *Link) ID() uuid.UUID {
	return l.id
}

// Listener returns the peer-to-peer Link's listener id
func (l *Link) Listener() uuid.UUID {
	return l.listener
}

// Type returns what type of peer-to-peer Link this is (e.g., TCP reverse or SMB bind)
func (l *Link) Type() int {
	return l.connType
}

// Remote returns the address the peer-to-peer Link is connected to
func (l *Link) Remote() net.Addr {
	return l.remote
}

// UpdateConn updates the peer-to-peer Link's network connection
// The updated object must be subsequently stored in the repository
func (l *Link) UpdateConn(conn interface{}, remote net.Addr) {
	l.conn = conn
	l.remote = remote
}

// String returns the peer-to-peer Link's type as a string
func (l *Link) String() string {
	return String(l.connType)
}

// String converts the peer-to-peer Link type from a constant to a string
func String(linkType int) string {
	switch linkType {
	case SMBREVERSE:
		return "smb-reverse"
	case SMBBIND:
		return "smb-bind"
	case TCPBIND:
		return "tcp-bind"
	case TCPREVERSE:
		return "tcp-reverse"
	case UDPBIND:
		return "udp-bind"
	case UDPREVERSE:
		return "udp-reverse"
	default:
		return fmt.Sprintf("unknown peer-to-peer agent link type %d", linkType)
	}
}
