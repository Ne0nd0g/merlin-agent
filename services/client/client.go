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

// Package client is a service to manager Merlin command and control communication clients
package client

import (
	"fmt"
	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/clients"
	"github.com/Ne0nd0g/merlin-agent/v2/clients/memory"
	"github.com/Ne0nd0g/merlin-message"
	"strings"
)

// Service is the structure used to interact with Client objects
type Service struct {
	ClientRepo clients.Repository
}

// memoryService is an in-memory instantiation of the client service
var memoryService *Service

// NewClientService is the factory to create a new service for working with Merlin C2 clients
func NewClientService() *Service {
	if memoryService == nil {
		memoryService = &Service{
			ClientRepo: withMemoryClientRepo(),
		}
	}
	return memoryService
}

// withMemoryClientRepo gets an in-memory Client repository structure and returns it
func withMemoryClientRepo() clients.Repository {
	return memory.NewRepository()
}

// Add saves the input Client into the repository
func (s *Service) Add(client clients.Client) {
	s.ClientRepo.Add(client)
}

// Authenticate initiates the Client's authentication function to authenticate this Agent to the Merlin server
// the input msg is used to pass authentication data when the authenticator requires multiple trips
func (s *Service) Authenticate(msg messages.Base) error {
	return s.ClientRepo.Get().Authenticate(msg)
}

// Connect instructs the Client to disconnect from its current server and connect to the new provided target
func (s *Service) Connect(addr string) (err error) {
	client := s.ClientRepo.Get()
	err = client.Set("addr", addr)
	return
}

// Get returns the Agent's current communication client from the repository
func (s *Service) Get() clients.Client {
	return s.ClientRepo.Get()
}

// Initial starts the Client's initialization route used to start a new connection with Merlin server
func (s *Service) Initial() error {
	return s.ClientRepo.Get().Initial()
}

// Listen executes a Client's protocol-specific function to listen for incoming messages and returns them
func (s *Service) Listen() ([]messages.Base, error) {
	return s.ClientRepo.Get().Listen()
}

// Reset resets the client's listener to its initial state to allow for a new connection
func (s *Service) Reset() (err error) {
	client := s.ClientRepo.Get()
	proto := client.Get("protocol")
	switch strings.ToLower(proto) {
	case "udp-bind":
		err = client.Set("bind", "")
	default:
		err = fmt.Errorf("services/client.Reset(): protocol %s not supported", proto)
	}
	return
}

// Send takes in a Base message and uses the Agent's Client to send it to the Merlin server or parent Agent
func (s *Service) Send(msg messages.Base) ([]messages.Base, error) {
	return s.ClientRepo.Get().Send(msg)
}

// SetJA3 updates the HTTP client's JA3 signature to the provided value
func (s *Service) SetJA3(ja3 string) error {
	return s.ClientRepo.SetJA3(ja3)
}

// SetListener updates the listener ID used with peer-to-peer clients
func (s *Service) SetListener(listener string) error {
	return s.ClientRepo.SetListener(listener)
}

// SetPadding updates the maximum amount of random padding added to each Base message
func (s *Service) SetPadding(padding string) error {
	return s.ClientRepo.SetPadding(padding)
}

// SetParrot updates the HTTP client's configuration to parrot the provided browser
func (s *Service) SetParrot(parrot string) error {
	return s.ClientRepo.SetParrot(parrot)
}

// Synchronous returns if the client doesn't sleep (synchronous) or if it does sleep (asynchronous)
func (s *Service) Synchronous() bool {
	return s.ClientRepo.Get().Synchronous()
}
