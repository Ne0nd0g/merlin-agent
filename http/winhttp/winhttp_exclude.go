//go:build !winhttp && (http2 || http3 || mythic || smb || tcp || udp || !windows)

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

package winhttp

import (
	"fmt"
	"net/http"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/http/http1"
)

// NewHTTPClient returns an HTTP/1.1 client using the Windows WinHTTP API
// A http.DefaultClient is returned if the platform is not Windows
func NewHTTPClient(protocol, proxyURL string, insecure bool) (*http.Client, error) {
	cli.Message(cli.DEBUG, "http/winhttp/winhttp.go/NewHTTPClient(): Entering into function...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Protocol: %s, Proxy: %s, insecure: %t", protocol, proxyURL, insecure))
	cli.Message(cli.WARN, "winhttp was not compiled into this binary, using http.DefaultClient")

	return http1.NewHTTPClient(protocol, proxyURL, insecure)
}
