//go:build !tcp && (http || http1 || http2 || http3 || mythic || winhttp || smb || udp)

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

// Package tcp contains a configurable client used for TCP-based peer-to-peer Agent communications
package tcp

import (
	// Standard
	"fmt"

	// 3rd Party
	"github.com/google/uuid"

	// Internal
	messages "github.com/Ne0nd0g/merlin-message"
)

// Client is a type of MerlinClient that is used to send and receive Merlin messages from the Merlin server
type Client struct {
}

// Config is a structure used to pass in all necessary information to instantiate a new Client
type Config struct {
	Address      []string  // Address the interface and port the agent will bind to
	AgentID      uuid.UUID // AgentID the Agent's UUID
	AuthPackage  string    // AuthPackage the type of authentication the agent should use when communicating with the server
	ListenerID   uuid.UUID // ListenerID the UUID of the listener that this Agent is configured to communicate with
	Padding      string    // Padding the max amount of data that will be randomly selected and appended to every message
	PSK          string    // PSK the Pre-Shared Key secret the agent will use to start authentication
	Transformers string    // Transformers is an ordered comma seperated list of transforms (encoding/encryption) to apply when constructing a message
	Mode         string    // Mode the type of client or communication mode (e.g., BIND or REVERSE)
}

// New instantiates and returns a Client that is constructed from the passed in Config
func New(Config) (*Client, error) {
	return nil, fmt.Errorf("clients/tcp.New(): TCP client not compiled into this program")
}

// Authenticate is the top-level function used to authenticate an agent to server using a specific authentication protocol
// The function must take in a Base message for when the C2 server requests re-authentication through a message
func (client *Client) Authenticate(messages.Base) (err error) {
	return fmt.Errorf("clients/tcp.Authenticate(): TCP client not compiled into this program")
}

// Get is a generic function used to retrieve the value of a Client's field
func (client *Client) Get(string) string {
	return fmt.Sprintf("clients/tcp.Get(): TCP client not compiled into this program")
}

// Initial executes the specific steps required to establish a connection with the C2 server and checkin or register an agent
func (client *Client) Initial() error {
	return fmt.Errorf("clients/tcp.Initial(): TCP client not compiled into this program")
}

// Listen waits for incoming data on an established TCP connection, deconstructs the data into a Base messages, and returns them
func (client *Client) Listen() (returnMessages []messages.Base, err error) {
	err = fmt.Errorf("clients/tcp.LIsten(): TCP client not compiled into this program")
	return
}

// Send takes in a Merlin message structure, performs any encoding or encryption, converts it to a delegate and writes it to the output stream.
// This function DOES not wait or listen for response messages.
func (client *Client) Send(messages.Base) (returnMessages []messages.Base, err error) {
	err = fmt.Errorf("clients/tcp.Send(): TCP client not compiled into this program")
	return
}

// Set is a generic function that is used to modify a Client's field values
func (client *Client) Set(key string, value string) error {
	return fmt.Errorf("clients/tcp.Set(): TCP client not compiled into this program")
}

// Synchronous identifies if the client connection is synchronous or asynchronous, used to determine how and when messages
// can be sent/received.
func (client *Client) Synchronous() bool {
	return false
}
