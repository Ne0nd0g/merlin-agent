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

// Package message is a service to process and return Agent Base messages
package message

import (
	// Standard
	"fmt"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/services/client"
	"github.com/Ne0nd0g/merlin-agent/v2/services/job"
	"github.com/Ne0nd0g/merlin-agent/v2/services/p2p"
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
var out = make(chan messages.Base, 100)

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
	return memoryService
}

// Check does not block but looks to see if there are any jobs or delegates that need to be returned to the Merlin server
func (s *Service) Check() (msg messages.Base) {
	cli.Message(cli.DEBUG, "services/message.Check(): entering into function")
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
	cli.Message(cli.DEBUG, fmt.Sprintf("services/message.Check(): leaving function with %+v", msg))
	return
}

// Get blocks until there is a return base message to send back to the Merlin server
func (s *Service) Get() (msg messages.Base) {
	cli.Message(cli.DEBUG, "services/message.Get(): entering into function")
	msg = <-out
	cli.Message(cli.DEBUG, fmt.Sprintf("services/message.Get(): leaving function with %+v", msg))
	return
}

// GetDelegates blocks waiting for a delegate message that needs to be returned to the Merlin server and adds it to the
// out channel as a Base message type of CHECKIN because it will not be aggregated with other return message types.
// Used when the Agent doesn't sleep and only communicates when there is a message to send
func (s *Service) GetDelegates() {
	cli.Message(cli.DEBUG, "services/message.getDelegates(): entering into function")
	defer cli.Message(cli.DEBUG, "services/message.getDelegates(): leaving function")
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

// GetJobs blocks waiting for a return job to exist, adds it to a Base message, and adds it to the out channel.
// Used when the Agent doesn't sleep and only communicates when there is a message to send
func (s *Service) GetJobs() {
	cli.Message(cli.DEBUG, "services/message.getJobs(): entering into function")
	defer cli.Message(cli.DEBUG, "services/message.getJobs(): leaving function")
	for {
		msg := messages.Base{
			ID:   s.Agent,
			Type: messages.JOBS,
		}
		msg.Payload = s.JobService.Get()
		cli.Message(cli.DEBUG, fmt.Sprintf("services/message.getJobs(): added message Base to outgoing message channel: %+v\n", msg))
		out <- msg
	}
}

// Handle processes incoming Base messages for this Agent
func (s *Service) Handle(msg messages.Base) (err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/messages.Handle(): Entering into function with: %+v", msg))
	defer cli.Message(cli.DEBUG, fmt.Sprintf("services/messages.Handle(): Leaving function with error: %+v", err))
	cli.Message(cli.SUCCESS, fmt.Sprintf("%s message type received!", msg.Type))

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
	case messages.CHECKIN:
		// Used when the Agent needs to force a checkin with the server by creating and sending a Checkin message
		out <- msg
	default:
		stdErr := fmt.Sprintf("%s is not a valid message type", msg.Type)
		s.JobService.AddResult(s.Agent, "", stdErr)
	}

	// If there are any Delegate messages, send them to the Handler
	if len(msg.Delegates) > 0 {
		// Use a go routine so that P2P functions don't block the Agent from continuing
		go s.P2PService.Handle(msg.Delegates)
	}
	return
}

// Store adds a Base message to the out channel to be sent back to the Merlin server
// Used when there is an error sending a message, and it needs to be preserved
func (s *Service) Store(msg messages.Base) {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/messages.Store(): Entering into function with: %+v", msg))
	defer cli.Message(cli.DEBUG, "services/messages.Store(): Leaving function...")
	out <- msg
}
