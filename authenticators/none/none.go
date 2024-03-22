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

// Package none is used to exclude or bypass authentication mechanisms. When this Authenticator is used, NO authentication is provided
package none

import (
	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"
)

// Authenticator is a structure used for "none" authentication
type Authenticator struct {
	agent uuid.UUID
}

// New returns a "none" Authenticator structure
func New(id uuid.UUID) *Authenticator {
	return &Authenticator{agent: id}
}

// Authenticate returns true because the none package offers no authentication
func (a *Authenticator) Authenticate(messages.Base) (messages.Base, bool, error) {
	return messages.Base{ID: a.agent, Type: messages.CHECKIN}, true, nil
}

// Secret returns an empty key because the none package offers no authentication and did not establish a secret
func (a *Authenticator) Secret() ([]byte, error) {
	return []byte{}, nil
}

// String returns the name of the Authenticator type
func (a *Authenticator) String() string {
	return "none"
}
