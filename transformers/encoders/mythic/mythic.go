//go:build mythic

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

// Package mythic encode/decode Agent messages to/from the Mythic C2 framework
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/agent-message-format
package mythic

import (
	"encoding/base64"
	"fmt"
)

type Coder struct {
}

// NewEncoder is a factory that returns a structure that implements the Transformer interface
func NewEncoder() *Coder {
	return &Coder{}
}

// Construct takes in data, prepends the UUID, base64 encodes it, and returns the encoded data as bytes
// id is the UUID as bytes to prepend to the data
func (c *Coder) Construct(data any, id []byte) ([]byte, error) {
	// UUID - This UUID varies based on the phase of the agent (initial checkin, staging, fully staged).
	// This is a 36-character long of the format b50a5fe8-099d-4611-a2ac-96d93e6ec77b.
	// Optionally, if your agent is dealing with more of a binary-level specification rather than strings, you can use
	// a 16-byte big-endian value here for the binary representation of the UUID4 string.
	// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/agent-message-format
	data = append(id, data.([]byte)...)

	// Base64 encode the data
	payload := base64.StdEncoding.EncodeToString(data.([]byte))
	return []byte(payload), nil
}

// Deconstruct takes in data, base64 decodes it, and returns the decoded data as bytes
// key is the UUID as bytes to prepend to the data
func (c *Coder) Deconstruct(data, id []byte) (any, error) {
	// Base64 decode the data
	payload, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	// Validate the UUID
	if string(payload[:36]) != string(id) {
		return nil, fmt.Errorf("transformers/encoders/mythic/http.Deconstruct(): UUID mismatch have: %s want: %s", string(payload[:36]), string(id))
	}
	// Remove the UUID
	payload = payload[36:]
	return payload, nil
}

// String returns the name of the encoder
func (c *Coder) String() string {
	return "mythic"
}
