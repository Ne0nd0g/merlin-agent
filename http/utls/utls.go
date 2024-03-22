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

/*
https://github.com/CUCyber/ja3transport/

MIT License

Copyright (c) 2019 CU Cyber

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package utls

import (
	// Standard
	"bufio"
	"context"
	"crypto/sha256"
	t "crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	// X-Packages
	"golang.org/x/net/http2"

	// 3rd Party
	tls "github.com/refraction-networking/utls"
)

// tlsExtensions is a TLSExtension objects associated with their extension number
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
var tlsExtensions = map[string]tls.TLSExtension{
	"0": &tls.SNIExtension{},
	"5": &tls.StatusRequestExtension{},
	// These are applied later
	// "10": &tls.SupportedCurvesExtension{...}
	// "11": &tls.SupportedPointsExtension{...}
	"13": &tls.SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
			tls.PKCS1WithSHA1,
		},
	},
	"16": &tls.ALPNExtension{
		AlpnProtocols: []string{"h2", "http/1.1"},
	},
	"17": &tls.StatusRequestV2Extension{},
	"18": &tls.SCTExtension{},
	//"21": &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	"21": &tls.UtlsPaddingExtension{GetPaddingLen: CustomPaddingStyle},
	"22": &tls.GenericExtension{Id: 22},
	"23": &tls.ExtendedMasterSecretExtension{},
	"24": &tls.FakeTokenBindingExtension{},
	"27": &tls.UtlsCompressCertExtension{},
	"28": &tls.FakeRecordSizeLimitExtension{},
	"34": &tls.FakeDelegatedCredentialsExtension{}, // delegated_credentials
	"35": &tls.SessionTicketExtension{},
	//"41": &tls.GenericExtension{Id: 41},
	"43": &tls.SupportedVersionsExtension{Versions: []uint16{
		tls.GREASE_PLACEHOLDER,
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10}},
	"44": &tls.CookieExtension{},
	"45": &tls.PSKKeyExchangeModesExtension{
		Modes: []uint8{
			tls.PskModeDHE,
		}},
	"51":    &tls.KeyShareExtension{KeyShares: []tls.KeyShare{}},
	"13172": &tls.NPNExtension{},
	"17513": &tls.ApplicationSettingsExtension{},
	"65281": &tls.RenegotiationInfoExtension{
		Renegotiation: tls.RenegotiateOnceAsClient,
	},
}

// NewTransportFromJA3 creates a new http.Transport object given an utls.Config
func NewTransportFromJA3(ja3 string, InsecureSkipVerify bool, proxy func(*http.Request) (*url.URL, error)) (*Transport, error) {
	spec, err := JA3toClientHello(ja3)
	if err != nil {
		return nil, err
	}

	tlsConfig := &t.Config{
		InsecureSkipVerify: InsecureSkipVerify, // #nosec G402 - intentionally configurable to allow self-signed certificates
	}

	transport := Transport{
		clientHello:     tls.HelloCustom,
		clientHelloSpec: spec,
		tr1:             http.Transport{MaxIdleConns: 10, IdleConnTimeout: 1 * time.Nanosecond, TLSClientConfig: tlsConfig},
		tr2:             http2.Transport{TLSClientConfig: tlsConfig},
		proxy:           proxy,
	}
	return &transport, nil
}

// NewTransportFromParrot takes in a string that represents a ClientHelloID to parrot a TLS connection that
// looks like an associated browser and returns a http transport structure
func NewTransportFromParrot(parrot string, InsecureSkipVerify bool, proxy func(*http.Request) (*url.URL, error)) (*Transport, error) {
	clientHello, err := ParrotStringToClientHelloID(parrot)
	if err != nil {
		return nil, err
	}

	tlsConfig := &t.Config{
		InsecureSkipVerify: InsecureSkipVerify, // #nosec G402 - intentionally configurable to allow self-signed certificates
	}

	transport := Transport{
		clientHello: clientHello,
		tr1:         http.Transport{MaxIdleConns: 10, IdleConnTimeout: 1 * time.Nanosecond, TLSClientConfig: tlsConfig},
		tr2:         http2.Transport{TLSClientConfig: tlsConfig},
		proxy:       proxy,
	}
	return &transport, nil
}

// JA3toClientHello creates a ClientHelloSpec based on a JA3 string
// JA3 string format: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
func JA3toClientHello(ja3 string) (*tls.ClientHelloSpec, error) {
	// Remove Unicode dashes
	// Unicode Hyphen U+2010
	ja3 = strings.ReplaceAll(ja3, "‐", "-")
	// Unicode Non-Breaking Hyphen U+2011
	ja3 = strings.ReplaceAll(ja3, "‑", "-")
	// Unicode En Dash U+2013
	ja3 = strings.ReplaceAll(ja3, "–", "-")

	// Split the JA3 string into tokens
	tokens := strings.Split(ja3, ",")
	if len(tokens) != 5 {
		return nil, fmt.Errorf("ja3transport: the provided ja3 string did not contain five comma separated fields")
	}

	// Parse JA3 string fields
	version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	pointFormats := strings.Split(tokens[4], "-")

	// Parse SSLVersion
	vid64, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("ja3transport: unable to convert SSLVersion %s to an integer: %s", version, err)
	}
	// Add SSLVersion to ClientHelloSpec structure
	clientHello := tls.ClientHelloSpec{
		TLSVersMin: uint16(vid64),
		TLSVersMax: uint16(vid64),
	}
	tlsExtensions["43"] = &tls.SupportedVersionsExtension{
		Versions: []uint16{uint16(vid64)},
	}

	// Parse CipherSuites
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("ja3transport: unable to convert CipherSuites %s to an integer: %s", c, err)
		}
		// Add CipherSuites to ClientHelloSpec structure
		clientHello.CipherSuites = append(clientHello.CipherSuites, uint16(cid))
	}

	// Parse EllipticCurve
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	} else if len(curves) > 0 {
		var targetCurves []tls.CurveID
		for _, c := range curves {
			cid, err := strconv.ParseUint(c, 10, 16)
			if err != nil {
				return nil, err
			}
			targetCurves = append(targetCurves, tls.CurveID(cid))
		}
		tlsExtensions["10"] = &tls.SupportedCurvesExtension{Curves: targetCurves}
	}

	// Parse EllipticCurvePointFormat
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	} else if len(pointFormats) > 0 {
		var targetPointFormats []byte
		for _, p := range pointFormats {
			pid, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				return nil, err
			}
			targetPointFormats = append(targetPointFormats, byte(pid))
		}
		tlsExtensions["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}
	}

	// Parse SSLExtension
	// Needs to happen AFTER elliptic curve data is added to the global extension map
	for _, e := range extensions {
		extension, ok := tlsExtensions[e]
		if !ok {
			return nil, fmt.Errorf("ja3transport: TLS extension %s does not exist in package extension map", e)
		}
		// Add SSLExtensions to ClientHelloSpec structure
		clientHello.Extensions = append(clientHello.Extensions, extension)
	}

	clientHello.GetSessionID = sha256.Sum256
	clientHello.CompressionMethods = []byte{0}
	return &clientHello, nil
}

// ParrotStringToClientHelloID reads in a string that represents a uTLS ClientHelloID and returns the real ClientHelloID object
// https://github.com/refraction-networking/utls/blob/8e1e65eb22d21c635523a31ec2bcb8730991aaad/u_common.go#L150
func ParrotStringToClientHelloID(parrot string) (clientHello tls.ClientHelloID, err error) {
	switch strings.ToLower(parrot) {
	// Valid options are tied to uTLS version 1.1.5
	case strings.ToLower("HelloGolang"):
		clientHello = tls.HelloGolang
	case strings.ToLower("HelloCustom"):
		clientHello = tls.HelloCustom
	case strings.ToLower("HelloRandomized"):
		clientHello = tls.HelloRandomized
	case strings.ToLower("HelloRandomizedALPN"):
		clientHello = tls.HelloRandomizedALPN
	case strings.ToLower("HelloRandomizedNoALPN"):
		clientHello = tls.HelloRandomizedNoALPN
	case strings.ToLower("HelloFirefox_Auto"):
		clientHello = tls.HelloFirefox_Auto
	case strings.ToLower("HelloFirefox_55"):
		clientHello = tls.HelloFirefox_55
	case strings.ToLower("HelloFirefox_56"):
		clientHello = tls.HelloFirefox_56
	case strings.ToLower("HelloFirefox_63"):
		clientHello = tls.HelloFirefox_63
	case strings.ToLower("HelloFirefox_65"):
		clientHello = tls.HelloFirefox_65
	case strings.ToLower("HelloFirefox_99"):
		clientHello = tls.HelloFirefox_99
	case strings.ToLower("HelloFirefox_102"):
		clientHello = tls.HelloFirefox_102
	case strings.ToLower("HelloFirefox_105"):
		clientHello = tls.HelloFirefox_105
	case strings.ToLower("HelloChrome_Auto"):
		clientHello = tls.HelloChrome_Auto
	case strings.ToLower("HelloChrome_58"):
		clientHello = tls.HelloChrome_58
	case strings.ToLower("HelloChrome_62"):
		clientHello = tls.HelloChrome_62
	case strings.ToLower("HelloChrome_70"):
		clientHello = tls.HelloChrome_70
	case strings.ToLower("HelloChrome_72"):
		clientHello = tls.HelloChrome_72
	case strings.ToLower("HelloChrome_83"):
		clientHello = tls.HelloChrome_83
	case strings.ToLower("HelloChrome_87"):
		clientHello = tls.HelloChrome_87
	case strings.ToLower("HelloChrome_96"):
		clientHello = tls.HelloChrome_96
	case strings.ToLower("HelloChrome_100"):
		clientHello = tls.HelloChrome_100
	case strings.ToLower("HelloChrome_102"):
		clientHello = tls.HelloChrome_102
	case strings.ToLower("HelloIOS_Auto"):
		clientHello = tls.HelloIOS_Auto
	case strings.ToLower("HelloIOS_11_1"):
		clientHello = tls.HelloIOS_11_1
	case strings.ToLower("HelloIOS_12_1"):
		clientHello = tls.HelloIOS_12_1
	case strings.ToLower("HelloIOS_13"):
		clientHello = tls.HelloIOS_13
	case strings.ToLower("HelloIOS_14"):
		clientHello = tls.HelloIOS_14
	case strings.ToLower("HelloAndroid_11_OkHttp"):
		clientHello = tls.HelloAndroid_11_OkHttp
	case strings.ToLower("HelloEdge_Auto"):
		clientHello = tls.HelloEdge_Auto
	case strings.ToLower("HelloEdge_85"):
		clientHello = tls.HelloEdge_85
	case strings.ToLower("HelloEdge_106"):
		clientHello = tls.HelloEdge_106
	case strings.ToLower("HelloSafari_Auto"):
		clientHello = tls.HelloSafari_Auto
	case strings.ToLower("HelloSafari_16_0"):
		clientHello = tls.HelloSafari_16_0
	case strings.ToLower("Hello360_Auto"):
		clientHello = tls.Hello360_Auto
	case strings.ToLower("Hello360_7_5"):
		clientHello = tls.Hello360_7_5
	case strings.ToLower("Hello360_11_0"):
		clientHello = tls.Hello360_11_0
	case strings.ToLower("HelloQQ_Auto"):
		clientHello = tls.HelloQQ_Auto
	case strings.ToLower("HelloQQ_11_1"):
		clientHello = tls.HelloQQ_11_1
	default:
		err = fmt.Errorf("ja3transport: unable to convert parrot string %s to a ClientHelloID", parrot)
	}
	return
}

// dialer is a custom Dialer that facilitates the use of a proxy
type dialer struct {
	address string   // Address to establish the network connection to
	conn    net.Conn // conn is TCP connection to the proxy
	network string   // Network is the network type to use when dialing the proxy, typically "tcp"
}

// DialContext establishes a TCP connection to the provided Address
// This package uses this function to establish a TCP connection to a proxy
// The function must implement the net.Dialer interface
// The input network and address parameters are ignored because they are for the source HTTP request, not the proxy request
func (d *dialer) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	utlsDialer := net.Dialer{
		Timeout: 30 * time.Second,
	}

	conn, err = utlsDialer.DialContext(ctx, d.network, d.address)
	if err != nil {
		err = fmt.Errorf("clients/utls/utls.go: there was an error dialing '%s:%s' for the request to '%s:%s': %s", d.network, d.address, network, address, err)
		return
	}
	d.conn = conn
	return
}

// Copied from @ox1234 via https://github.com/refraction-networking/utls/issues/16

// Transport is custom http.Transport that switches clients between HTTP/1.1 and HTTP2 depending on which protocol
// was negotiated during the TLS handshake.
// It is also used to create a http.Transport structure from a JA3 or parrot string
type Transport struct {
	tr1             http.Transport
	tr2             http2.Transport
	mu              sync.RWMutex
	clientHello     tls.ClientHelloID
	clientHelloSpec *tls.ClientHelloSpec
	proxy           func(*http.Request) (*url.URL, error)
}

// RoundTrip completes the TLS handshake and creates a http client depending on the negotiated http version during the
// TLS handshake (e.g., http/1.1 or h2). After the handshake, the HTTP request is sent to the destination.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var conn net.Conn
	var err error

	// If there is no proxy, establish the TCP connection
	if t.proxy == nil {
		// Identify what port to connect to for manually establishing the TCP connection
		address := req.URL.Host
		if req.URL.Port() == "" {
			if req.URL.Scheme == "http" {
				address = fmt.Sprintf("%s:80", req.URL.Host)
			} else {
				address = fmt.Sprintf("%s:443", req.URL.Host)
			}
		}
		conn, err = net.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("clients/utls/utls.go RoundTrip(): %w", err)
		}
	} else {
		// If there is a proxy, sent the HTTP CONNECT method request before establishing the TLS connection

		// Get the proxy URL
		var proxyURL *url.URL
		proxyURL, err = t.proxy(req)
		if err != nil {
			return nil, fmt.Errorf("clients/utls/utls.go RoundTrip(): there was an error getting the proxy URL: %s", err)
		}

		// If the proxy URL is nil, then this request does not use the proxy
		// Send CONNECT request to proxy
		if proxyURL != nil {
			// Set up the custom dialer
			u := dialer{
				network: "tcp",
				address: proxyURL.Host,
			}

			// Set up the custom transport
			trans := &http.Transport{
				DisableCompression: true,
				DialContext:        u.DialContext,
			}

			// Build the CONNECT request for the proxy
			var proxyReq *http.Request
			// The protocol should match the protocol the proxy is expecting and host:port should be the destination
			connectURL := fmt.Sprintf("%s://%s", proxyURL.Scheme, req.URL.Host)
			proxyReq, err = http.NewRequest(http.MethodConnect, connectURL, nil)
			if err != nil {
				return nil, fmt.Errorf("clients/utls/utls.go RoundTrip(): there was an error creating the CONNECT request: %w", err)
			}
			proxyReq.Header.Set("User-Agent", req.UserAgent())

			// Send the CONNECT request to the proxy
			var resp *http.Response
			resp, err = trans.RoundTrip(proxyReq)
			if err != nil {
				return nil, fmt.Errorf("clients/utls/utls.go RoundTrip(): there was an error sending the CONNECT request: %w", err)
			}

			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("clients/utls/utls.go RoundTrip(): there was an error sending the CONNECT request: %s", resp.Status)
			}
			conn = u.conn
		}
	}

	// Complete the TLS handshake
	uConn, err := t.tlsConnect(conn, req)
	if err != nil {
		return nil, fmt.Errorf("tls connect fail: %w", err)
	}

	switch uConn.ConnectionState().NegotiatedProtocol {
	case "h2":
		var h2Conn *http2.ClientConn
		h2Conn, err = t.tr2.NewClientConn(uConn)
		if err != nil {
			return nil, fmt.Errorf("clients/utls/utls.go RoundTrip(): there was an error creating a new HTTP/2 client connection: %w", err)
		}
		return h2Conn.RoundTrip(req)
	case "http/1.1", "":
		err = req.Write(uConn)
		if err != nil {
			return nil, fmt.Errorf("write http1 tls connection fail: %w", err)
		}
		return http.ReadResponse(bufio.NewReader(uConn), req)
	default:
		return nil, fmt.Errorf("clients/utls/utls.go RoundTrip(): unsuported http version: %s", uConn.ConnectionState().NegotiatedProtocol)
	}
}

// tlsConnect gets a uTLS client from the transports JA3 or parrot string and executes just the TLS handshake
func (t *Transport) tlsConnect(conn net.Conn, req *http.Request) (*tls.UConn, error) {
	t.mu.RLock()
	config := &tls.Config{
		ServerName:         req.URL.Host,
		InsecureSkipVerify: t.tr1.TLSClientConfig.InsecureSkipVerify,
	}

	tlsConn := tls.UClient(conn, config, t.clientHello)
	// Apply the custom TLS configuration to the connection if it exists
	if t.clientHelloSpec != nil {
		err := tlsConn.ApplyPreset(t.clientHelloSpec)
		if err != nil {
			t.mu.RUnlock()
			return nil, fmt.Errorf("there was an error applying the uTLS ClientHelloSpec: %s", err)
		}
	}
	t.mu.RUnlock()

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake fail: %w", err)
	}
	return tlsConn, nil
}

// CustomPaddingStyle is a function to use with TLS extension ID 21, padding.
// In order to ensure this TLS extension is always enabled, the function never returns 0 or false like the
// BoringPaddingStyle function in the uTLS library does. Returns a random number between 0 and 65,535
// Adapted from https://github.com/refraction-networking/utls/blob/8e1e65eb22d21c635523a31ec2bcb8730991aaad/u_tls_extensions.go#L680
// https://www.rfc-editor.org/rfc/rfc7685.html
func CustomPaddingStyle(unpaddedLen int) (int, bool) {
	pad, _ := tls.BoringPaddingStyle(unpaddedLen)
	if pad > 0 {
		return pad, true
	}
	// #nosec G404 -- Random number does not impact security
	return rand.Intn(65535), true
}
