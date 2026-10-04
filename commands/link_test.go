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

package commands

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"net"
	"testing"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/p2p"
)

// tlvFrame wraps payload in the TLV framing Connect() expects on the wire:
// a 4-byte big-endian tag (always 1) followed by an 8-byte big-endian length,
// then the payload itself.
func tlvFrame(payload []byte) []byte {
	tag := make([]byte, 4)
	binary.BigEndian.PutUint32(tag, 1)
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(len(payload)))
	frame := append(tag, length...)
	return append(frame, payload...)
}

// startPeer starts a TCP listener that accepts a single connection, writes
// response to it, and then holds the connection open until the test finishes
// (so the listen() goroutine Connect() spawns on success simply blocks on Read
// rather than racing teardown). It returns the dial address.
func startPeer(t *testing.T, response []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start test peer: %s", err)
	}
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write(response)
		<-done
		_ = conn.Close()
	}()
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
	})
	return ln.Addr().String()
}

// TestConnectTCPSuccess verifies the happy path: given a well-formed, GOB-encoded
// Delegate response, Connect() reports success and registers the link.
func TestConnectTCPSuccess(t *testing.T) {
	var buf bytes.Buffer
	delegate := messages.Delegate{Agent: uuid.New(), Listener: uuid.New()}
	if err := gob.NewEncoder(&buf).Encode(delegate); err != nil {
		t.Fatalf("could not gob-encode the delegate: %s", err)
	}

	addr := startPeer(t, tlvFrame(buf.Bytes()))

	results := Connect("tcp", []string{addr})

	if results.Stderr != "" {
		t.Fatalf("Connect() returned an unexpected error: %s", results.Stderr)
	}
	if results.Stdout == "" {
		t.Fatal("Connect() returned empty Stdout on a successful link")
	}
	if _, ok := peerToPeerService.Connected(p2p.TCPBIND, addr); !ok {
		t.Fatalf("Connect() did not register a TCPBIND link to %s", addr)
	}
}

// TestConnectTCPDecodeError is the regression test for the previously-swallowed
// GOB decode error: a well-framed response whose payload is not a valid GOB
// stream must surface an error via results.Stderr (it used to be written to a
// local variable and silently dropped), and must not report success.
func TestConnectTCPDecodeError(t *testing.T) {
	addr := startPeer(t, tlvFrame([]byte("this is not a valid gob stream")))

	results := Connect("tcp", []string{addr})

	if results.Stderr == "" {
		t.Fatal("Connect() swallowed a GOB decode error: expected results.Stderr to be set")
	}
	if results.Stdout != "" {
		t.Fatalf("Connect() reported success despite a decode error: %s", results.Stdout)
	}
}
