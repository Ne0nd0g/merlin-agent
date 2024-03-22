//go:build http || winhttp || !(http2 || http3 || mythic || smb || tcp || udp)

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

// Package winhttp provides HTTP clients using the Windows WinHTTP API
package winhttp

import (
	// Standard
	"crypto/tls"
	"fmt"
	"net/http"

	// 3rd Party
	winhttp2 "github.com/Ne0nd0g/winhttp"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// NewHTTPClient returns an HTTP/1.1 client using the Windows WinHTTP API
func NewHTTPClient(protocol, proxyURL string, insecure bool) (*winhttp2.Client, error) {
	cli.Message(cli.DEBUG, "http/winhttp/winhttp_windows.go/NewHTTPClient(): Entering into function...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Protocol: %s, Proxy: %s, insecure: %t", protocol, proxyURL, insecure))
	client, err := winhttp2.NewHTTPClient()
	if err != nil {
		return nil, err
	}
	tlsConfig := tls.Config{
		Rand:                        nil,
		Time:                        nil,
		Certificates:                nil,
		GetCertificate:              nil,
		GetClientCertificate:        nil,
		GetConfigForClient:          nil,
		VerifyPeerCertificate:       nil,
		VerifyConnection:            nil,
		RootCAs:                     nil,
		NextProtos:                  nil,
		ServerName:                  "",
		ClientAuth:                  0,
		ClientCAs:                   nil,
		InsecureSkipVerify:          insecure,
		CipherSuites:                nil,
		SessionTicketsDisabled:      false,
		ClientSessionCache:          nil,
		UnwrapSession:               nil,
		WrapSession:                 nil,
		MinVersion:                  0,
		MaxVersion:                  0,
		CurvePreferences:            nil,
		DynamicRecordSizingDisabled: false,
		Renegotiation:               0,
		KeyLogWriter:                nil,
	}
	transport := http.Transport{
		Proxy:                  nil,
		OnProxyConnectResponse: nil,
		DialContext:            nil,
		DialTLSContext:         nil,
		TLSClientConfig:        &tlsConfig,
		TLSHandshakeTimeout:    0,
		DisableKeepAlives:      false,
		DisableCompression:     false,
		MaxIdleConns:           0,
		MaxIdleConnsPerHost:    0,
		MaxConnsPerHost:        0,
		IdleConnTimeout:        0,
		ResponseHeaderTimeout:  0,
		ExpectContinueTimeout:  0,
		TLSNextProto:           nil,
		ProxyConnectHeader:     nil,
		GetProxyConnectHeader:  nil,
		MaxResponseHeaderBytes: 0,
		WriteBufferSize:        0,
		ReadBufferSize:         0,
		ForceAttemptHTTP2:      false,
	}
	client.Transport = &transport
	return client, nil
}
