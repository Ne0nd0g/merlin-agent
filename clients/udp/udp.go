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

// Package udp contains a configurable client used for UDP-based peer-to-peer Agent communications
package udp

import (
	// Standard
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/messages"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/authenticators"
	"github.com/Ne0nd0g/merlin-agent/authenticators/none"
	"github.com/Ne0nd0g/merlin-agent/authenticators/opaque"
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin-agent/core"
	transformer "github.com/Ne0nd0g/merlin-agent/transformers"
	gob2 "github.com/Ne0nd0g/merlin-agent/transformers/encoders/gob"
	"github.com/Ne0nd0g/merlin-agent/transformers/encrypters/aes"
	"github.com/Ne0nd0g/merlin-agent/transformers/encrypters/jwe"
)

const (
	BIND    = 0
	REVERSE = 1
)

// Client is a type of MerlinClient that is used to send and receive Merlin messages from the Merlin server
type Client struct {
	address       string                       // address is the network interface and port the agent will bind to
	agentID       uuid.UUID                    // agentID the Agent's UUID
	authenticated bool                         // authenticated tracks if the Agent has successfully authenticated
	authenticator authenticators.Authenticator // authenticator the method the Agent will use to authenticate to the server
	client        net.Addr                     // client is the address of the UDP client that initiated the connection, returned from PacketConn.ReadFrom
	connection    net.Conn                     // connection the network socket connection used to handle traffic
	listener      net.PacketConn               // listener the network socket connection listening for traffic
	listenerID    uuid.UUID                    // listenerID the UUID of the listener that this Agent is configured to communicate with
	paddingMax    int                          // paddingMax the maximum amount of random padding to apply to every Base message
	psk           string                       // psk the pre-shared key used for encrypting messages until authentication is complete
	secret        []byte                       // secret the key used to encrypt messages
	transformers  []transformer.Transformer    // Transformers an ordered list of transforms (encoding/encryption) to apply when constructing a message
	mode          int                          // mode the type of client or communication mode (e.g., BIND or REVERSE)
}

// Config is a structure that is used to pass in all necessary information to instantiate a new Client
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
func New(config Config) (*Client, error) {
	cli.Message(cli.DEBUG, "Entering into clients/udp.New()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Config: %+v", config))
	client := Client{}
	if config.AgentID == uuid.Nil {
		return nil, fmt.Errorf("clients/udp.New(): a nil Agent UUID was provided")
	}
	client.agentID = config.AgentID
	if config.ListenerID == uuid.Nil {
		return nil, fmt.Errorf("clients/udp.New(): a nil Listener UUID was provided")
	}

	switch strings.ToLower(config.Mode) {
	case "udp-bind":
		client.mode = BIND
	case "udp-reverse":
		client.mode = REVERSE
	default:
		client.mode = BIND
	}

	client.listenerID = config.ListenerID
	client.psk = config.PSK

	// Parse Address and validate it
	if len(config.Address) <= 0 {
		return nil, fmt.Errorf("a configuration address value was not provided")
	}
	_, err := net.ResolveUDPAddr("udp", config.Address[0])
	if err != nil {
		return nil, err
	}
	client.address = config.Address[0]

	// Set secret for encryption
	k := sha256.Sum256([]byte(client.psk))
	client.secret = k[:]
	cli.Message(cli.DEBUG, fmt.Sprintf("new client PSK: %s", client.psk))
	cli.Message(cli.DEBUG, fmt.Sprintf("new client Secret: %x", client.secret))

	//Convert Padding from string to an integer
	if config.Padding != "" {
		client.paddingMax, err = strconv.Atoi(config.Padding)
		if err != nil {
			return &client, fmt.Errorf("there was an error converting the padding max to an integer:\r\n%s", err)
		}
	} else {
		client.paddingMax = 0
	}

	// Authenticator
	switch strings.ToLower(config.AuthPackage) {
	case "opaque":
		client.authenticator = opaque.New(config.AgentID)
	case "none":
		client.authenticator = none.New(config.AgentID)
	default:
		return nil, fmt.Errorf("an authenticator must be provided (e.g., 'opaque'")
	}

	// Transformers
	transforms := strings.Split(config.Transformers, ",")
	for _, transform := range transforms {
		var t transformer.Transformer
		switch strings.ToLower(transform) {
		case "gob-base":
			t = gob2.NewEncoder(gob2.BASE)
		case "gob-string":
			t = gob2.NewEncoder(gob2.STRING)
		case "aes":
			t = aes.NewEncrypter()
		case "jwe":
			t = jwe.NewEncrypter()
		default:
			err := fmt.Errorf("clients/udp.New(): unhandled transform type: %s", transform)
			if err != nil {
				return nil, err
			}
		}
		client.transformers = append(client.transformers, t)
	}

	cli.Message(cli.INFO, "Client information:")
	cli.Message(cli.INFO, fmt.Sprintf("\tProtocol: %s", &client))
	cli.Message(cli.INFO, fmt.Sprintf("\tAddress: %s", client.address))
	cli.Message(cli.INFO, fmt.Sprintf("\tListener: %s", client.listenerID))
	cli.Message(cli.INFO, fmt.Sprintf("\tAuthenticator: %s", client.authenticator))
	cli.Message(cli.INFO, fmt.Sprintf("\tTransforms: %+v", client.transformers))
	cli.Message(cli.INFO, fmt.Sprintf("\tPadding: %d", client.paddingMax))

	return &client, nil
}

// Initial executes the specific steps required to establish a connection with the C2 server and checkin or register an agent
func (client *Client) Initial() error {
	cli.Message(cli.DEBUG, "Entering clients/udp.Initial() function")

	err := client.Connect()
	if err != nil {
		return fmt.Errorf("clients/udp.Initial(): %s", err)
	}

	// Authenticate
	err = client.Authenticate(messages.Base{})
	return err
}

// Authenticate is the top-level function used to authenticate an agent to server using a specific authentication protocol
// The function must take in a Base message for when the C2 server requests re-authentication through a message
func (client *Client) Authenticate(msg messages.Base) (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/udp.Authenticate(): entering into function with message: %+v", msg))
	var authenticated bool
	// Reset the Agent's PSK
	k := sha256.Sum256([]byte(client.psk))
	client.secret = k[:]

	// Repeat until authenticator is complete and Agent is authenticated
	for {
		msg, authenticated, err = client.authenticator.Authenticate(msg)
		if err != nil {
			return
		}

		// Once authenticated, update the client's secret used to encrypt messages
		if authenticated {
			client.authenticated = true
			var key []byte
			key, err = client.authenticator.Secret()
			if err != nil {
				return
			}
			// Don't update the secret if the authenticator returned an empty key
			if len(key) > 0 {
				client.secret = key
			}
		}

		if msg.Type == messages.OPAQUE {
			// Send the message to the server
			var msgs []messages.Base
			msgs, err = client.SendAndWait(msg)
			if err != nil {
				return
			}

			// Add response message to the next loop iteration
			if len(msgs) > 0 {
				// Don't add IDLE messages, just continue on
				if msgs[0].Type != messages.IDLE {
					msg = msgs[0]
				}
			}
		} else {
			_, err = client.Send(msg)
			if err != nil {
				return
			}
		}

		// If the Agent is authenticated, exit the loop and return the function
		if authenticated {
			return
		}
	}
}

// Connect establish a connection with the remote host depending on the Client's type (e.g., BIND or REVERSE)
func (client *Client) Connect() (err error) {
	switch client.mode {
	case BIND:
		// Will hit this if connection was lost during initialization steps because a Listener will already exist
		if client.listener == nil {
			client.listener, err = net.ListenPacket("udp", client.address)
			if err != nil {
				return fmt.Errorf("clients/udp.Connect(): there was an error listening on %s: %s", client.address, err)
			}
			cli.Message(cli.NOTE, fmt.Sprintf("Started %s listener on %s", client, client.address))
		}
		var n int
		buffer := make([]byte, 500000)
		cli.Message(cli.NOTE, fmt.Sprintf("Listening for incoming connection..."))
		n, client.client, err = client.listener.ReadFrom(buffer)
		cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from %s", n, client.client))
		if err != nil {
			return fmt.Errorf("clients/udp.Connect(): there was an error reading data from %s : %s", client.client, err)
		}

		return
	case REVERSE:
		client.connection, err = net.Dial("udp", client.address)
		if err != nil {
			return fmt.Errorf("clients/udp.Connect(): there was an error connecting to %s: %s", client.address, err)
		}
		client.client = client.connection.RemoteAddr()
		cli.Message(cli.NOTE, fmt.Sprintf("successfully connected to %s", client.address))
		return
	default:
		return fmt.Errorf("clients/udp.Connect(): unhandled UDP client mode: %d", client.mode)
	}
}

// Construct takes in a messages.Base structure that is ready to be sent to the server and runs all the configured transforms
// on it to encode and encrypt it.
func (client *Client) Construct(msg messages.Base) (data []byte, err error) {
	for i := len(client.transformers); i > 0; i-- {
		if i == len(client.transformers) {
			// First call should always take a Base message
			data, err = client.transformers[i-1].Construct(msg, client.secret)
		} else {
			data, err = client.transformers[i-1].Construct(data, client.secret)
		}
		if err != nil {
			return nil, fmt.Errorf("clients/udp.Construct(): there was an error calling the transformer construct function: %s", err)
		}
	}
	return
}

// Deconstruct takes in data returned from the server and runs all the Agent's transforms on it until
// a messages.Base structure is returned. The key is used for decryption transforms
func (client *Client) Deconstruct(data []byte) (messages.Base, error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/udp.Deconstruct(): entering into function with message: %+v", data))
	//fmt.Printf("Deconstructing %d bytes with key: %x\n", len(data), client.secret)
	for _, transform := range client.transformers {
		//fmt.Printf("Transformer %T: %+v\n", transform, transform)
		ret, err := transform.Deconstruct(data, client.secret)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("clients/udp.Deconstruct(): unable to deconstruct with Agent's secret, retrying with PSK"))
			// Try to see if the PSK works
			k := sha256.Sum256([]byte(client.psk))
			ret, err = transform.Deconstruct(data, k[:])
			if err != nil {
				return messages.Base{}, err
			}
			// If the PSK worked, assume the agent is unauthenticated to the server
			client.authenticated = false
			client.secret = k[:]
		}
		switch ret.(type) {
		case []uint8:
			data = ret.([]byte)
		case string:
			data = []byte(ret.(string)) // Probably not what I should be doing
		case messages.Base:
			//fmt.Printf("pkg/listeners.Deconstruct(): returning Base message: %+v\n", ret.(messages.Base))
			return ret.(messages.Base), nil
		default:
			return messages.Base{}, fmt.Errorf("clients/udp.Deconstruct(): unhandled data type for Deconstruct(): %T", ret)
		}
	}
	return messages.Base{}, fmt.Errorf("clients/udp.Deconstruct(): unable to transform data into messages.Base structure")
}

func (client *Client) Listen() (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients/udp.Listen()")

	cli.Message(cli.NOTE, fmt.Sprintf("Listening for incoming messages from %s at %s...", client.client, time.Now().UTC().Format(time.RFC3339)))

	respData := make([]byte, 500000)
	readTimeout := time.Minute * 5
	var n int

	switch client.mode {
	case BIND:
		n, client.client, err = client.listener.ReadFrom(respData)
	case REVERSE:
		err = client.connection.SetReadDeadline(time.Now().Add(readTimeout))
		if err != nil {
			cli.Message(cli.DEBUG, fmt.Sprintf("clients/udp.Listen(): there was an error setting the connection read deadline to 5 minutes: %s", err))
		}
		n, err = client.connection.Read(respData)
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from connection %s at %s", n, client.client, time.Now().UTC().Format(time.RFC3339)))
	if err != nil {
		switch err2 := err.(type) {
		case net.Error:
			if err2.Timeout() {
				err = fmt.Errorf("clients/udp.Listen(): The UDP connection read time of %s was reached: %s", readTimeout, err)
				return
			}
		default:
			err = fmt.Errorf("clients/udp.Listen(): there was an error reading the message from the connection with %s: %s", client.client, err)
		}
		return
	}

	var msg messages.Base
	msg, err = client.Deconstruct(respData[:n])
	if err != nil {
		err = fmt.Errorf("clients/udp.Listen(): there was an error deconstructing the data: %s", err)
		cli.Message(cli.DEBUG, err.Error())
		// See if the data was from initial link command from another agent
		b64 := make([]byte, base64.StdEncoding.EncodedLen(n))
		_, errBase64 := base64.StdEncoding.Decode(b64, respData[:n])
		if errBase64 == nil {
			cli.Message(cli.INFO, fmt.Sprintf("Received Base64 encoded string from %s. Treating as a new connection...", client.client))
			// Send gratuitous checkin to provide parent Agent with linked agent data
			if client.authenticated {
				_, err = client.Send(messages.Base{ID: client.agentID, Type: messages.CHECKIN})
			}
			return
		}
		return
	}

	//fmt.Printf("Received message: %+v\n", msg)
	returnMessages = append(returnMessages, msg)
	return
}

// Send takes in a Merlin message structure, performs any encoding or encryption, converts it to a delegate and writes it to the output stream
// The function also decodes and decrypts response messages and return a Merlin message structure.
// This is where the client's logic is for communicating with the server.
func (client *Client) Send(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients/udp.Send()")
	cli.Message(cli.NOTE, fmt.Sprintf("Sending %s message to %s at %s", messages.String(m.Type), client.client, time.Now().UTC().Format(time.RFC3339)))

	// Set the message padding
	if client.paddingMax > 0 {
		// #nosec G404 -- Random number does not impact security
		m.Padding = core.RandStringBytesMaskImprSrc(rand.Intn(client.paddingMax))
	}

	data, err := client.Construct(m)
	if err != nil {
		err = fmt.Errorf("clients/udp.Send(): there was an error constructing the data: %s", err)
		return
	}

	delegate := messages.Delegate{
		Listener: client.listenerID,
		Agent:    client.agentID,
		Payload:  data,
	}

	// Convert messages.Base to gob
	// Still need this for agent to agent message encoding
	delegateBytes := new(bytes.Buffer)
	err = gob.NewEncoder(delegateBytes).Encode(delegate)
	if err != nil {
		err = fmt.Errorf("clients/udp.Send(): there was an error encoding the %s message to a gob:\r\n%s", messages.String(m.Type), err)
		return
	}

	// Recover connection
	if client.connection == nil && client.mode == REVERSE {
		err = client.Connect()
		if err != nil {
			err = fmt.Errorf("clients/udp.Send(): %s", err)
			return
		}
	}

	// Write the message
	cli.Message(cli.DEBUG, fmt.Sprintf("Writing message size: %d to: %s at %s", delegateBytes.Len(), client.client, time.Now().UTC().Format(time.RFC3339)))
	var n int
	switch client.mode {
	case BIND:
		n, err = client.listener.WriteTo(delegateBytes.Bytes(), client.client)
	case REVERSE:
		n, err = client.connection.Write(delegateBytes.Bytes())
	}

	if err != nil {
		err = fmt.Errorf("clients/udp.Send(): there was an error writing the message to the connection with %s: %s", client.client, err)
		return
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("Wrote %d bytes to connection %s at %s", n, client.client, time.Now().UTC().Format(time.RFC3339)))

	return
}

// SendAndWait takes in a Merlin message, encodes/encrypts it, and writes it to the output stream and then waits for response
// messages and returns them
func (client *Client) SendAndWait(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients/udp.SendAndWait()...")

	// Send
	returnMessages, err = client.Send(m)
	if err != nil {
		err = fmt.Errorf("clients/udp.SendAndWait(): %s", err)
		return
	}

	// Listen
	return client.Listen()
}

// Get is a generic function that is used to retrieve the value of a Client's field
func (client *Client) Get(key string) string {
	cli.Message(cli.DEBUG, "Entering into clients/udp.Get()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s", key))
	switch strings.ToLower(key) {
	case "paddingmax":
		return strconv.Itoa(client.paddingMax)
	case "protocol":
		return client.String()
	default:
		return fmt.Sprintf("unknown client configuration setting: %s", key)
	}
}

// Set is a generic function that is used to modify a Client's field values
func (client *Client) Set(key string, value string) error {
	cli.Message(cli.DEBUG, "Entering into clients/udp.Set()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s, Value: %s", key, value))
	var err error
	switch strings.ToLower(key) {
	case "listener":
		var id uuid.UUID
		id, err = uuid.FromString(value)
		if err != nil {
			return fmt.Errorf("clients/udp.Set(): %s", err)
		}
		client.listenerID = id
	case "paddingmax":
		client.paddingMax, err = strconv.Atoi(value)
	case "secret":
		client.secret = []byte(value)
	default:
		err = fmt.Errorf("unknown udp client setting: %s", key)
	}
	return err
}

// String returns the type of UDP client
func (client *Client) String() string {
	switch client.mode {
	case BIND:
		return "udp-bind"
	case REVERSE:
		return "udp-reverse"
	default:
		return "udp-unhandled"
	}
}

func (client *Client) Synchronous() bool {
	switch client.mode {
	case BIND:
		return true
	case REVERSE:
		return true
	default:
		return false
	}
}
