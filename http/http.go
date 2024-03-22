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

// Package http provides HTTP clients for various HTTP protocols and operating systems
package http

import (
	// Standard
	"fmt"
	"github.com/Ne0nd0g/merlin-agent/v2/http/http3"
	"net/http"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/http/http1"
	"github.com/Ne0nd0g/merlin-agent/v2/http/http2"
	"github.com/Ne0nd0g/merlin-agent/v2/http/proxy"
	"github.com/Ne0nd0g/merlin-agent/v2/http/utls"
	"github.com/Ne0nd0g/merlin-agent/v2/http/winhttp"
)

// Type is the type of HTTP client to use from the constants in this package (e.g., HTTP, H2C, WINHTTP, etc.)
type Type int

// Supported protocols
const (
	// UNDEFINED is the default value when a Type was not set
	UNDEFINED Type = iota
	// HTTP is HTTP/1.1 Clear-Text protocol
	HTTP
	// HTTPS is HTTP/1.1 Secure (over SSL/TLS) protocol
	HTTPS
	// H2C is HTTP/2.0 Clear-Text protocol
	H2C
	// HTTP2 is HTTP/2.0 Secure (over SSL/TLS)
	HTTP2
	// HTTP3 is HTTP/2.0 Secure over Quick UDP Internet Connection (QUIC)
	HTTP3
	// WINHTTP uses the Windows WinHTTP API
	WINHTTP
	// WININET uses the Windows WinINet API
	WININET
	// JA3 uses the JA3 fingerprinting library
	JA3
	// PARROT uses the Parrot HTTP client
	PARROT
)

// Config is the configuration for the HTTP client
type Config struct {
	ClientType Type
	Insecure   bool
	JA3        string
	Parrot     string
	Protocol   string
	ProxyURL   string
	ProxyUser  string
	ProxyPass  string
}

// Client is the interface for the HTTP client designed to mimic the http.Client
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewHTTPClient creates a new HTTP client that implements the Client interface based on the configuration
func NewHTTPClient(config Config) (client Client, err error) {
	switch config.ClientType {
	case HTTP, HTTPS:
		return http1.NewHTTPClient(config.Protocol, config.ProxyURL, config.Insecure)
	case HTTP2, H2C:
		return http2.NewHTTPClient(config.Protocol, config.Insecure)
	case HTTP3:
		return http3.NewHTTPClient(config.Insecure)
	case WINHTTP:
		return winhttp.NewHTTPClient(config.Protocol, config.ProxyURL, config.Insecure)
	case JA3:
		// Proxy
		proxyFunc, errProxy := proxy.GetProxy(config.Protocol, config.ProxyURL)
		if errProxy != nil {
			return nil, errProxy
		}

		var transport *utls.Transport
		transport, err = utls.NewTransportFromJA3(config.JA3, config.Insecure, proxyFunc)
		if err != nil {
			return nil, err
		}
		return &http.Client{Transport: transport}, nil
	case PARROT:
		// Proxy
		proxyFunc, errProxy := proxy.GetProxy(config.Protocol, config.ProxyURL)
		if errProxy != nil {
			return nil, errProxy
		}

		var transport *utls.Transport
		transport, err = utls.NewTransportFromParrot(config.Parrot, config.Insecure, proxyFunc)
		if err != nil {
			return nil, err
		}
		return &http.Client{Transport: transport}, nil
	case UNDEFINED:
		return nil, fmt.Errorf("http/http.go/NewHTTPClient(): client type was not set")
	default:
		return nil, fmt.Errorf("http/http.go/NewHTTPClient(): client type '%s:%d' is un handled", config.ClientType, config.ClientType)
	}
}

// String converts a protocol type constant to its string representation
func (t Type) String() string {
	switch t {
	case UNDEFINED:
		return "UNDEFINED"
	case HTTP:
		return "HTTP"
	case HTTPS:
		return "HTTPS"
	case H2C:
		return "H2C"
	case HTTP2:
		return "HTTP2"
	case HTTP3:
		return "HTTP3"
	case WINHTTP:
		return "WINHTTP"
	case WININET:
		return "WININET"
	case JA3:
		return "JA3"
	case PARROT:
		return "PARROT"
	default:
		return "UNDEFINED"
	}
}
