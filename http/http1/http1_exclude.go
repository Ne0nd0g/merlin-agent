//go:build !http1 && !mythic && (http2 || http3 || winhttp || smb || tcp || udp)

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
	"fmt"
	"net/http"
)

// NewHTTPClient returns an HTTP/1.1 client using the Go standard library
func NewHTTPClient(protocol, proxyURL string, insecure bool) (*http.Client, error) {
	return nil, fmt.Errorf("http/http1/http1_exclude.go/NewHTTPClient(): HTTP/1 client not compiled into this program")
}
