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

// Package authenticators holds the factories to create structures that implement the Authenticator interface
// This interface is used by the Agent to authenticate to the server
package authenticators

import (
	// Merlin
	"github.com/Ne0nd0g/merlin-message"
)

// Authenticator is an interface used by various authentication methods
type Authenticator interface {
	// Authenticate performs the necessary steps to authenticate the agent, returning one or more Base messages needed
	// to complete authentication. Function must take in a Base message for when the authentication process takes more
	// than one step.
	Authenticate(messages.Base) (messages.Base, bool, error)
	// Secret returns encryption keys derived during the Agent authentication process (if applicable)
	Secret() ([]byte, error)
	// String returns a string representation of the Authenticator's type
	String() string
}
