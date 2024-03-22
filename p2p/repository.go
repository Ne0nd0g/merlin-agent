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

package p2p

import (
	// Standard
	"net"

	// 3rd Party
	"github.com/google/uuid"
)

type Repository interface {
	// Delete removes the peer-to-peer Link from the in-memory datastore
	Delete(id uuid.UUID)
	// Get finds the peer-to-peer Link by the provided id and returns it
	Get(id uuid.UUID) (link *Link, err error)
	// GetAll returns all peer-to-peer Links in the in-memory datastore
	GetAll() (links []*Link)
	// Store saves the provided peer-to-peer link into the in-memory datastore
	Store(link *Link)
	// UpdateConn updates the peer-to-peer Link's embedded conn field with the provided network connection
	UpdateConn(id uuid.UUID, conn interface{}, remote net.Addr) error
}
