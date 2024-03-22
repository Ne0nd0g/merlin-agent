//go:build http || http1 || mythic || !(http2 || http3 || winhttp || smb || tcp || udp)

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

// Package http1 provides an HTTP/1.1 client using the Go standard library
package http1

import (
	// Standard
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/http/proxy"
)

// NewHTTPClient returns an HTTP/1.1 client using the Go standard library
func NewHTTPClient(protocol, proxyURL string, insecure bool) (*http.Client, error) {
	cli.Message(cli.DEBUG, "http/http1/http1.go/NewHTTPClient(): Entering into function...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Protocol: %s, Proxy: %s, insecure: %t", protocol, proxyURL, insecure))
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
	proxyFunc, errProxy := proxy.GetProxy(protocol, proxyURL)
	if errProxy != nil {
		return nil, errProxy
	}

	var transport http.RoundTripper
	switch strings.ToLower(protocol) {
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
