//go:build !windows

/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023 Russel Van Tuyl

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

// Package smb contains a configurable client used for Windows-based SMB peer-to-peer Agent communications
package smb

import (
	// Standard
	"fmt"
	"net"
	"runtime"
	"sync"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/authenticators"
	transformer "github.com/Ne0nd0g/merlin-agent/v2/transformers"
)

// Client is a type of MerlinClient that is used to send and receive Merlin messages from the Merlin server
type Client struct {
	address       string                       // address is the SMB named pipe the agent will bind to
	agentID       uuid.UUID                    // agentID the Agent's UUID
	authenticated bool                         // authenticated tracks if the Agent has successfully authenticated
	authenticator authenticators.Authenticator // authenticator the method the Agent will use to authenticate to the server
	connection    net.Conn                     // connection the network socket connection used to handle traffic
	listener      net.Listener                 // listener the network socket connection listening for traffic
	listenerID    uuid.UUID                    // listenerID the UUID of the listener that this Agent is configured to communicate with
	paddingMax    int                          // paddingMax the maximum amount of random padding to apply to every Base message
	psk           string                       // psk the pre-shared key used for encrypting messages until authentication is complete
	secret        []byte                       // secret the key used to encrypt messages
	transformers  []transformer.Transformer    // Transformers an ordered list of transforms (encoding/encryption) to apply when constructing a message
	mode          int                          // mode the type of client or communication mode (e.g., BIND or REVERSE)
	sync.Mutex                                 // used to lock the Client when changes are being made by one function or routine
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
	return nil, fmt.Errorf("clients/smb.New(): this function is not supported by the %s operating system", runtime.GOOS)
}

// Authenticate is the top-level function used to authenticate an agent to server using a specific authentication protocol
// The function must take in a Base message for when the C2 server requests re-authentication through a message
func (client *Client) Authenticate(messages.Base) (err error) {
	return fmt.Errorf("clients/smb.Authenticate(): the smb client is not supported for the %s operating system", runtime.GOOS)
}

// Get is a generic function used to retrieve the value of a Client's field
func (client *Client) Get(string) string {
	return fmt.Sprintf("clients/smb.Get(): the smb client is not supported for the %s operating system", runtime.GOOS)
}

// Initial executes the specific steps required to establish a connection with the C2 server and checkin or register an agent
func (client *Client) Initial() error {
	return fmt.Errorf("clients/smb.Initial(): the smb client is not supported for the %s operating system", runtime.GOOS)
}

// Listen waits for incoming data on an established TCP connection, deconstructs the data into a Base messages, and returns them
func (client *Client) Listen() (returnMessages []messages.Base, err error) {
	err = fmt.Errorf("clients/smb.LIsten(): the smb client is not supported for the %s operating system", runtime.GOOS)
	return
}

// Send takes in a Merlin message structure, performs any encoding or encryption, converts it to a delegate and writes it to the output stream.
// This function DOES not wait or listen for response messages.
func (client *Client) Send(messages.Base) (returnMessages []messages.Base, err error) {
	err = fmt.Errorf("clients/smb.Send(): the smb client is not supported for the %s operating system", runtime.GOOS)
	return
}

// Set is a generic function that is used to modify a Client's field values
func (client *Client) Set(key string, value string) error {
	return fmt.Errorf("clients/smb.Set(): the smb client is not supported for the %s operating system", runtime.GOOS)
}

// Synchronous identifies if the client connection is synchronous or asynchronous, used to determine how and when messages
// can be sent/received.
func (client *Client) Synchronous() bool {
	return false
}
