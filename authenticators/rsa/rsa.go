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

// Package rsa is an authenticator for Agent communications with the server using RSA key exchange
// Primarily used with Mythic's HTTP profile
package rsa

import (
	// Standard
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/x509"
	"encoding/base64"
	"fmt"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin Message
	messages "github.com/Ne0nd0g/merlin-message"
	rsa2 "github.com/Ne0nd0g/merlin-message/rsa"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/core"
)

// Authenticator is a structure used for OPAQUE authentication
type Authenticator struct {
	agent         uuid.UUID      // agent is the Agent's unique ID
	authenticated bool           // authenticated is a boolean value that determines if the Agent is authenticated
	key           rsa.PrivateKey // key is the Agent's RSA private key
	secret        []byte         // The encryption key derived during the Agent authentication process
	session       string         // The session ID used for the current authentication process
}

// New returns an RSA Authenticator structure used for Agent authentication
func New(id uuid.UUID, key rsa.PrivateKey) *Authenticator {
	return &Authenticator{
		agent:   id,
		key:     key,
		session: core.RandStringBytesMaskImprSrc(20),
	}
}

// Authenticate performs the necessary steps to authenticate the agent, returning one or more Base messages needed
// to complete authentication. Function must take in a Base message for when the authentication process takes more
// than one step.
func (a *Authenticator) Authenticate(msg messages.Base) (messages.Base, bool, error) {
	if msg.Type == messages.KEYEXCHANGE {
		p := msg.Payload.(rsa2.Response)
		if p.SessionID != a.session {
			return messages.Base{}, false, fmt.Errorf("invalid RSA session ID '%s', expecting '%s'", p.SessionID, a.session)
		}

		// Base64 decode the session key
		key, err := base64.StdEncoding.DecodeString(p.SessionKey)
		if err != nil {
			err = fmt.Errorf("there was an error Base64 decoding the RSA session key:\n%s", err)
			return messages.Base{}, false, err
		}

		// Decrypt with an RSA private key and update the authenticator's secret key to use this session key
		hash := sha1.New() // #nosec G401
		a.secret, err = rsa.DecryptOAEP(hash, rand.Reader, &a.key, key, nil)
		if err != nil {
			err = fmt.Errorf("there was an error decrypting the returned RSA session key:\n%s", err)
			return messages.Base{}, false, err
		}

		a.authenticated = true

		// Mythic returns a new UUID for authenticated Agents
		m := messages.Base{
			ID: uuid.MustParse(p.ID),
		}
		return m, a.authenticated, nil
	}

	// RSA Key Exchange
	rsaRequest := rsa2.Request{
		Action:    "staging_rsa", // Specific to Mythic
		PubKey:    base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&a.key.PublicKey)),
		SessionID: a.session,
	}

	// Merlin Base message
	base := messages.Base{
		ID:      a.agent,
		Type:    messages.KEYEXCHANGE,
		Payload: rsaRequest,
	}
	return base, a.authenticated, nil
}

// Secret returns encryption keys derived during the Agent authentication process (if applicable)
func (a *Authenticator) Secret() ([]byte, error) {
	if !a.authenticated {
		return nil, fmt.Errorf("agent is not authenticated")
	}
	return a.secret, nil
}

// String returns a string representation of the Authenticator's type
func (a *Authenticator) String() string {
	return "RSA"
}
