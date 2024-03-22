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

package clients

type Repository interface {
	// Add stores the Client structure
	Add(client Client)
	// Get returns a copy of the current Client structure
	Get() Client
	// SetJA3 reconfigures the client's TLS fingerprint to match the provided JA3 string
	SetJA3(ja3 string) error
	// SetListener changes the client's upstream listener ID, a UUID, to the value provided
	SetListener(listener string) error
	// SetPadding changes the maximum amount of random padding added to each outgoing message
	SetPadding(padding string) error
	// SetParrot reconfigures the client's HTTP configuration to match the provided browser
	SetParrot(parrot string) error
}
