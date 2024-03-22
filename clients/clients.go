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

// Package clients holds the interface for network communications
package clients

import (
	// Merlin
	"github.com/Ne0nd0g/merlin-message"
)

// Client is an interface definition a client must implement to interact with a remote server
type Client interface {
	// Authenticate executes the configured authentication method sending the necessary messages to the server to
	// complete authentication. Function takes in a Base message for when the server returns information to continue the
	// process or needs to re-authenticate.
	Authenticate(msg messages.Base) error
	// Get retrieve's a client's configured option
	Get(key string) string
	// Initial contains all the steps the agent and/or the communication profile need to take to set up and initiate
	// communication with server
	Initial() error
	// Listen is used by synchronous Agents to consistently listen for new incoming messages that aren't the result of a check in
	Listen() ([]messages.Base, error)
	// Send takes in a Base message, transforms it according to the configured encoders/encrypters, and sends the message
	// at the infrastructure layer according to the client's protocol
	Send(base messages.Base) ([]messages.Base, error)
	// Set updates a client's configured options
	Set(key string, value string) error
	// Synchronous identifies if the client connection is synchronous or asynchronous, used to determine how and when messages
	// can be sent/received.
	Synchronous() bool
}
