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

// Package memory is an in-memory repository to store or update an Agent object

package memory

import (
	// Standard
	"sync"
	"time"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/agent"
)

// Repository is the structure that implements the in-memory repository for interacting with the Agent's C2 client
type Repository struct {
	sync.Mutex
	agent agent.Agent
}

// repo is the in-memory datastore
var repo *Repository

// NewRepository creates and returns a new in-memory repository for interacting with the Agent in-memory repository
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			Mutex: sync.Mutex{},
		}
	}
	return repo
}

// Add stores the Merlin Agent structure to the repository
func (r *Repository) Add(agent agent.Agent) {
	r.Lock()
	defer r.Unlock()
	r.agent = agent
}

// Get returns the stored Agent structure
func (r *Repository) Get() agent.Agent {
	return r.agent
}

// SetAuthenticated updates the Agent's authentication status and stores the updated Agent in the repository
func (r *Repository) SetAuthenticated(authenticated bool) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetAuthenticated(authenticated)
}

// SetFailedCheckIn updates the number of times the Agent has actually failed to check in and stores the updated Agent
// in the repository
func (r *Repository) SetFailedCheckIn(failed int) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetFailedCheckIn(failed)
}

// SetInitialCheckIn updates the time stamp that the Agent first successfully connected to the Merlin server and stores
// the updated Agent in the repository
func (r *Repository) SetInitialCheckIn(checkin time.Time) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetInitialCheckIn(checkin)
}

// SetKillDate sets the date, as an epoch timestamp, of when the Agent will quit running and stores the updated Agent
// in the repository
func (r *Repository) SetKillDate(epochDate int64) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetKillDate(epochDate)
}

// SetMaxRetry updates the number of times the Agent can fail to check in before it quits running and stores the updated
// Agent in the repository
func (r *Repository) SetMaxRetry(retries int) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetMaxRetry(retries)
}

// SetSkew updates the amount of jitter or skew added to the Agent's sleep or wait time and stores the updated Agent in
// the repository
func (r *Repository) SetSkew(skew int64) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetSkew(skew)
}

// SetSleep updates the amount of time the Agent will wait or sleep before it attempts to check in again and stores the
// updated Agent in the repository
func (r *Repository) SetSleep(sleep time.Duration) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetWaitTime(sleep)
}

// SetComms updates the Agent's embedded Comms structure with the one provided and stores the updated Agent in the repository
func (r *Repository) SetComms(comms agent.Comms) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetComms(comms)
}

// SetStatusCheckIn updates the last time the Agent successfully communicated with the Merlin server and stores the
// updated Agent in the repository
func (r *Repository) SetStatusCheckIn(checkin time.Time) {
	r.Lock()
	defer r.Unlock()
	r.agent.SetStatusCheckIn(checkin)
}
