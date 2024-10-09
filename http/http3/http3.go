//go:build http || http3 || !(http2 || mythic || winhttp || smb || tcp || udp)

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

// Package http3 provides an HTTP/2 over QUIC, known as HTTP/3, client
package http3

import (
	// Standard
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	// 3rd Party
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// NewHTTPClient returns an HTTP/3 client
func NewHTTPClient(insecure bool) (*http.Client, error) {
	cli.Message(cli.DEBUG, "http/http3/http3.go/NewHTTPClient(): Entering into function...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Insecure: %t", insecure))
	// Setup TLS configuration
	TLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, // #nosec G402 - intentionally configurable to allow self-signed certificates. See https://github.com/Ne0nd0g/merlin/issues/59
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	TLSConfig.NextProtos = []string{"h3"} // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	transport := &http3.RoundTripper{
		QUICConfig: &quic.Config{
			// Opted for a long timeout to prevent the client from sending a PING Frame.
			// If MaxIdleTimeout is too high, agent will never get an error if the server is offline and will perpetually run without exiting because MaxFailedCheckins is never incremented
			MaxIdleTimeout: time.Second * 30,
			// KeepAlivePeriod will send an HTTP/2 PING frame to keep the connection alive
			// If this isn't used, and the agent's sleep is greater than the MaxIdleTimeout, then the connection will time out
			KeepAlivePeriod: time.Second * 30,
			// HandshakeIdleTimeout is how long the client will wait to hear back while setting up the initial crypto handshake w/ server
			HandshakeIdleTimeout: time.Second * 30,
		},
		TLSClientConfig: TLSConfig,
	}
	return &http.Client{Transport: transport}, nil
}
