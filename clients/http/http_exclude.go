//go:build !http && !http1 && !http2 && !http3 && !winhttp && !mythic && (smb || tcp || udp)

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

// Package http implements the Client interface and contains the structures and functions to communicate to the Merlin
// server over the HTTP protocol
package http

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
	AgentID      uuid.UUID // AgentID the Agent's UUID
	Protocol     string    // Protocol contains the transportation protocol the agent is using (i.e., http2 or smb-reverse)
	Host         string    // Host is used with the HTTP Host header for Domain Fronting activities
	Headers      string    // Headers is a new-line separated string of additional HTTP headers to add to client requests
	URL          []string  // URL is the protocol, domain, and page that the agent will communicate with (e.g., https://google.com/test.aspx)
	Proxy        string    // Proxy is the URL of the proxy that all traffic needs to go through, if applicable
	ProxyUser    string    // ProxyUser is the username for the proxy, if applicable
	ProxyPass    string    // ProxyPass is the password for the proxy, if applicable
	UserAgent    string    // UserAgent is the HTTP User-Agent header string that Agent will use while sending traffic
	Parrot       string    // Parrot is a feature of the github.com/refraction-networking/utls to mimic a specific browser
	PSK          string    // PSK is the Pre-Shared Key secret the agent will use to start authentication
	JA3          string    // JA3 is a string that represents how the TLS client should be configured, if applicable
	Padding      string    // Padding is the max amount of data that will be randomly selected and appended to every message
	AuthPackage  string    // AuthPackage is the type of authentication the agent should use when communicating with the server
	Opaque       []byte    // Opaque is the byte representation of the EnvU object used with the OPAQUE protocol (future use)
	Transformers string    // Transformers is an ordered comma seperated list of transforms (encoding/encryption) to apply when constructing a message
	InsecureTLS  bool      // InsecureTLS is a boolean that determines if the InsecureSkipVerify flag is set to true or false
	ClientType   string    // ClientType is the type of WINDOWS http client to use (e.g., WinINet, WinHTTP, etc.)
}

// New instantiates and returns a Client constructed from the passed in Config
func New(config Config) (*Client, error) {
	return nil, fmt.Errorf("clients/http.New(): HTTP client not compiled into this program")
}

// Listen waits for incoming data on an established connection, deconstructs the data into a Base messages, and returns them
func (client *Client) Listen() (returnMessages []messages.Base, err error) {
	err = fmt.Errorf("clients/http.Listen(): the HTTP client does not support the Listen function")
	return
}

// Send takes in a Merlin message structure, performs any encoding or encryption, and sends it to the server.
// The function also decodes and decrypts response messages and returns a Merlin message structure.
// This is where the client's logic is for communicating with the server.
func (client *Client) Send(m messages.Base) (returnMessages []messages.Base, err error) {
	err = fmt.Errorf("clients/http.New(): HTTP client not compiled into this program")
	return
}

// Set is a generic function used to modify a Client's field values
func (client *Client) Set(key string, value string) (err error) {
	err = fmt.Errorf("clients/http.Set(): HTTP client not compiled into this program")
	return
}

// Get is a generic function used to retrieve the value of a Client's field
func (client *Client) Get(key string) (value string) {
	return fmt.Sprintf("clients/http.Get(): HTTP client not compiled into this program")
}

// Authenticate is the top-level function used to authenticate an agent to server using a specific authentication protocol
// The function must take in a Base message for when the C2 server requests re-authentication through a message
func (client *Client) Authenticate(msg messages.Base) (err error) {
	err = fmt.Errorf("clients/http.Authenticate(): HTTP client not compiled into this program")
	return
}

// Construct takes in a messages.Base structure that is ready to be sent to the server and runs all the configured transforms
// on it to encode and encrypt it. Transforms will go from last in the slice to first in the slice
func (client *Client) Construct(msg messages.Base) (data []byte, err error) {
	err = fmt.Errorf("clients/http.Construct(): HTTP client not compiled into this program")
	return
}

// Deconstruct takes in data returned from the server and runs all the Agent's transforms on it until
// a messages.Base structure is returned. The key is used for decryption transforms
func (client *Client) Deconstruct(data []byte) (messages.Base, error) {
	return messages.Base{}, fmt.Errorf("clients/http.Deconstruct(): HTTP client not compiled into this program")
}

// Initial contains all the steps the agent and/or the communication profile need to take to set up and initiate
// communication with the server.
// If the agent needs to authenticate before it can send messages, that process will occur here.
func (client *Client) Initial() (err error) {
	err = fmt.Errorf("clients/http.Initial(): HTTP client not compiled into this program")
	return
}

// Synchronous identifies if the client connection is synchronous or asynchronous, used to determine how and when messages
// can be sent/received.
func (client *Client) Synchronous() bool {
	return false
}
