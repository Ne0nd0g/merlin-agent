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

// Package agent is a service to manage Agent structures
package agent

import (
	// Standard
	"strconv"
	"time"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/agent"
	"github.com/Ne0nd0g/merlin-agent/v2/agent/memory"
	"github.com/Ne0nd0g/merlin-agent/v2/clients"
	clientMemory "github.com/Ne0nd0g/merlin-agent/v2/clients/memory"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	"github.com/Ne0nd0g/merlin-message"
)

// Service is the structure used to interact with Agent objects
type Service struct {
	AgentRepo  agent.Repository
	ClientRepo clients.Repository
}

// memoryService is an in-memory instantiation of the agent service
var memoryService *Service

// NewAgentService is a factory that returns an Agent Service
func NewAgentService() *Service {
	if memoryService == nil {
		memoryService = &Service{
			AgentRepo:  withAgentMemoryRepository(),
			ClientRepo: withClientMemoryRepository(),
		}
	}
	return memoryService
}

// withAgentMemoryRepository gets an in-memory Agent repository structure and returns it
func withAgentMemoryRepository() agent.Repository {
	return memory.NewRepository()
}

// withClientMemoryRepository gets an in-memory Agent Client repository structure and returns it
func withClientMemoryRepository() clients.Repository {
	return clientMemory.NewRepository()
}

// Add stores the provided agent object in the repository
func (s *Service) Add(agent agent.Agent) {
	s.AgentRepo.Add(agent)
}

// AgentInfo builds an AgentInfo structure from the information stored in the Agent and Client repositories
func (s *Service) AgentInfo() messages.AgentInfo {
	a := s.AgentRepo.Get()
	comms := a.Comms()
	h := a.Host()
	p := a.Process()
	c := s.ClientRepo.Get()

	sysInfoMessage := messages.SysInfo{
		HostName:     h.Name,
		Platform:     h.Platform,
		Architecture: h.Architecture,
		Ips:          h.IPs,
		Process:      p.Name,
		Pid:          p.ID,
		Integrity:    p.Integrity,
		UserName:     p.UserName,
		UserGUID:     p.UserGUID,
		Domain:       p.Domain,
	}

	padding, _ := strconv.Atoi(c.Get("paddingmax"))
	agentInfoMessage := messages.AgentInfo{
		Version:       core.Version,
		Build:         core.Build,
		WaitTime:      comms.Wait.String(),
		PaddingMax:    padding,
		MaxRetry:      comms.Retry,
		FailedCheckin: comms.Failed,
		Skew:          comms.Skew,
		Proto:         c.Get("protocol"),
		SysInfo:       sysInfoMessage,
		KillDate:      comms.Kill,
		JA3:           c.Get("ja3"),
	}
	return agentInfoMessage
}

// Get returns the single Agent object stored in the repository, because there can only be one
func (s *Service) Get() agent.Agent {
	return s.AgentRepo.Get()
}

// IncrementFailed increases the Agent's failed checkin count by one
func (s *Service) IncrementFailed() {
	a := s.AgentRepo.Get()
	c := a.Comms()
	c.Failed++
	s.AgentRepo.SetComms(c)
}

// SetAuthenticated updates the Agent's authenticated status
func (s *Service) SetAuthenticated(authenticated bool) {
	s.AgentRepo.SetAuthenticated(authenticated)
}

// SetFailedCheckIn updates the number of times the Agent has already failed to check in with the provided value
func (s *Service) SetFailedCheckIn(failed int) {
	s.AgentRepo.SetFailedCheckIn(failed)
}

// SetInitialCheckIn updates the time stamp of when the Agent first successfully check in
func (s *Service) SetInitialCheckIn(checkin time.Time) {
	s.AgentRepo.SetInitialCheckIn(checkin)
}

// SetKillDate updates the date, as an epoch timestamp, that the Agent will quit running
func (s *Service) SetKillDate(date int64) {
	s.AgentRepo.SetKillDate(date)
}

// SetMaxRetry updates the number of times the Agent can fail to check in before it quits running
func (s *Service) SetMaxRetry(retries int) {
	s.AgentRepo.SetMaxRetry(retries)
}

// SetSkew updates the amount of jitter or skew that is applied to an Agent's sleep time
func (s *Service) SetSkew(skew int64) {
	s.AgentRepo.SetSkew(skew)
}

// SetSleep updates the amount of time an Agent will sleep between checkins
func (s *Service) SetSleep(sleep time.Duration) {
	s.AgentRepo.SetSleep(sleep)
}

// SetStatusCheckIn updates the time stamp of when this Agent last successfully connected to the Server or parent Agent
func (s *Service) SetStatusCheckIn(checkin time.Time) {
	s.AgentRepo.SetStatusCheckIn(checkin)
}
