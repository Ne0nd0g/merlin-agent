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

package proxy

import (
	// Standard
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// GetProxy returns a proxy function for the passed in protocol and proxy URL if any
// Reads the HTTP_PROXY and HTTPS_PROXY environment variables if no proxy URL was passed in
func GetProxy(protocol string, proxyURL string) (func(*http.Request) (*url.URL, error), error) {
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
