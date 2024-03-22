//go:build !http2 && (http3 || mythic || winhttp || smb || tcp || udp)

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

package http2

import (
	// Standard
	"fmt"
	"net/http"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// NewHTTPClient returns an HTTP/1.1 client using the Go standard library
// NewHTTPClient returns an HTTP/2 client
func NewHTTPClient(protocol string, insecure bool) (*http.Client, error) {
	cli.Message(cli.DEBUG, "http/http2/http2_exclude.go/NewHTTPClient(): Entering into function...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Protocol: %s, Insecure: %t", protocol, insecure))
	return nil, fmt.Errorf("http/http2/http2_exclude.go/NewHTTPClient(): HTTP/2 client not compiled into this program")
}
