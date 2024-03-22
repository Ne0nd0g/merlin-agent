//go:build http || http2 || !(http3 || mythic || winhttp || smb || tcp || udp)

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

// Package http2 provides an HTTP/2 client
package http2

import (
	// Standard
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	// X Packages
	"golang.org/x/net/http2"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// NewHTTPClient returns an HTTP/2 client
func NewHTTPClient(protocol string, insecure bool) (*http.Client, error) {
	cli.Message(cli.DEBUG, "http/http2/http2.go/NewHTTPClient(): Entering into function...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Protocol: %s, Insecure: %t", protocol, insecure))
	// Setup TLS configuration
	TLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, // #nosec G402 - intentionally configurable to allow self-signed certificates. See https://github.com/Ne0nd0g/merlin/issues/59
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	var transport http.RoundTripper
	switch strings.ToLower(protocol) {
	case "h2", "http2":
		TLSConfig.NextProtos = []string{"h2"} // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
		transport = &http2.Transport{
			TLSClientConfig: TLSConfig,
		}
	case "h2c":
		transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}
	default:
		return nil, fmt.Errorf("%s is not a valid client protocol", protocol)
	}
	return &http.Client{Transport: transport}, nil
}
