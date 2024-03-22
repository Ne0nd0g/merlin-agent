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

// Package memory is an in-memory repository for storing and managing peer-to-peer Link objects
package memory

import (
	// Standard
	"fmt"
	"net"
	"sync"

	// 3rd Party
	"github.com/google/uuid"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/p2p"
)

// Repository holds database of existing peer-to-peer Links in a map
type Repository struct {
	sync.Mutex
	links sync.Map
}

// repo is the in-memory datastore
var repo *Repository

// NewRepository creates and returns a new in-memory repository for interacting with peer-to-peer Links
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			Mutex: sync.Mutex{},
		}
	}
	return repo
}

// Delete removes the peer-to-peer Link from the in-memory datastore
func (r *Repository) Delete(id uuid.UUID) {
	r.links.Delete(id)
}

// Get finds the peer-to-peer Link by the provided id and returns it
func (r *Repository) Get(id uuid.UUID) (link *p2p.Link, err error) {
	a, ok := r.links.Load(id)
	if !ok {
		err = fmt.Errorf("p2p/memory.Get(): %s is not a known P2P link", id)
		return
	}
	link = a.(*p2p.Link)
	return
}

// GetAll returns all peer-to-peer Links in the in-memory datastore
func (r *Repository) GetAll() (links []*p2p.Link) {
	r.links.Range(
		func(k, v interface{}) bool {
			agent := v.(*p2p.Link)
			links = append(links, agent)
			return true
		},
	)
	return
}

// Store saves the provided peer-to-peer link into the in-memory datastore
func (r *Repository) Store(link *p2p.Link) {
	r.links.Store(link.ID(), link)
}

// UpdateConn updates the peer-to-peer Link's embedded conn field with the provided network connection
func (r *Repository) UpdateConn(id uuid.UUID, conn interface{}, remote net.Addr) error {
	r.Lock()
	defer r.Unlock()
	link, err := r.Get(id)
	if err != nil {
		return fmt.Errorf("p2p/memory.UpdateConn(): %s", err)
	}
	link.UpdateConn(conn, remote)
	r.Store(link)
	return nil
}
