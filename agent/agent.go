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

package agent

import (
	// Standard
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	merlinOS "github.com/Ne0nd0g/merlin-agent/v2/os"
)

// Agent is an aggregate structure that represents a Merlin Agent
type Agent struct {
	id            uuid.UUID // id is a Universally Unique Identifier per agent
	authenticated bool      // authenticated identifies if the agent has successfully completed initial authentication (if applicable)
	checkin       time.Time // checkin is a timestamp of the agent's last status check in time
	comms         Comms     // comms holds information about the Agent's communications with the Server or parent Agent
	host          Host      // Host is an embedded structure that contains information about the host the Agent is running on
	initial       time.Time // initial is a timestamp of the agent's initial check in time
	process       Process   // Process contains information about this Agent's process
}

// Config is a structure that is used to pass in all necessary information to instantiate a new Agent
type Config struct {
	Sleep    string // Sleep is the amount of time the Agent will wait between sending messages to the server
	Skew     string // Skew is the variance or jitter, used to vary the sleep time so that it isn't constant
	KillDate string // KillDate is the date as a Unix timestamp, that agent will quit running
	MaxRetry string // MaxRetry is the maximum amount of time an agent will fail to check in before it quits running
}

// New creates a new Agent struct from the provided Config structure and returns the Agent object
func New(config Config) (agent Agent, err error) {
	cli.Message(cli.DEBUG, "Entering agent.New() function")

	agent = Agent{
		id: uuid.New(),
	}

	agent.host = Host{
		Architecture: runtime.GOARCH,
		Platform:     runtime.GOOS,
	}

	agent.process = Process{
		ID: os.Getpid(),
	}

	// Process integrity Level
	agent.process.Integrity, err = merlinOS.GetIntegrityLevel()
	if err != nil {
		cli.Message(cli.DEBUG, fmt.Sprintf("there was an error determining the agent's integrity level: %s", err))
	}

	// Process username and User GUID
	var u *user.User
	u, err = user.Current()
	if err != nil {
		err = fmt.Errorf("there was an error getting the current user: %s", err)
		return
	}
	agent.process.UserName = u.Username
	agent.process.UserGUID = u.Gid

	// Process Name
	agent.process.Name, err = os.Executable()
	if err != nil {
		err = fmt.Errorf("there was an error getting the process name: %s", err)
		return
	}

	agent.host.Name, err = os.Hostname()
	if err != nil {
		err = fmt.Errorf("there was an error getting the hostname: %s", err)
		return
	}

	var interfaces []net.Interface
	interfaces, err = net.Interfaces()
	if err != nil {
		err = fmt.Errorf("there was an error getting the IP addresses: %s", err)
		return
	}

	for _, iface := range interfaces {
		var addrs []net.Addr
		addrs, err = iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				agent.host.IPs = append(agent.host.IPs, addr.String())
			}
		} else {
			err = fmt.Errorf("there was an error getting interface information: %s", err)
			return
		}
	}

	// Parse config

	// Parse KillDate
	if config.KillDate != "" {
		agent.comms.Kill, err = strconv.ParseInt(config.KillDate, 10, 64)
		if err != nil {
			err = fmt.Errorf("there was an error converting the killdate to an integer: %s", err)
			return
		}
	} else {
		agent.comms.Kill = 0
	}

	// Parse MaxRetry
	if config.MaxRetry != "" {
		agent.comms.Retry, err = strconv.Atoi(config.MaxRetry)
		if err != nil {
			err = fmt.Errorf("there was an error converting the max retry to an integer: %s", err)
			return
		}
	} else {
		agent.comms.Retry = 7
	}

	// Parse Sleep
	if config.Sleep != "" {
		agent.comms.Wait, err = time.ParseDuration(config.Sleep)
		if err != nil {
			err = fmt.Errorf("there was an error converting the sleep time to an integer: %s", err)
			return
		}
	} else {
		agent.comms.Wait = 30000 * time.Millisecond
	}

	// Parse Skew
	if config.Skew != "" {
		agent.comms.Skew, err = strconv.ParseInt(config.Skew, 10, 64)
		if err != nil {
			err = fmt.Errorf("there was an error converting the skew to an integer: %s", err)
			return
		}
	} else {
		agent.comms.Skew = 3000
	}

	cli.Message(cli.INFO, "Host Information:")
	cli.Message(cli.INFO, fmt.Sprintf("\tAgent UUID: %s", agent.id))
	cli.Message(cli.INFO, fmt.Sprintf("\tHostname: %s", agent.host.Name))
	cli.Message(cli.INFO, fmt.Sprintf("\tPlatform: %s", agent.host.Platform))
	cli.Message(cli.INFO, fmt.Sprintf("\tArchitecture: %s", agent.host.Architecture))
	cli.Message(cli.INFO, fmt.Sprintf("\tPID: %d", agent.process.ID))
	cli.Message(cli.INFO, fmt.Sprintf("\tProcess: %s", agent.process.Name))
	cli.Message(cli.INFO, fmt.Sprintf("\tUser Name: %s", agent.process.UserName))
	cli.Message(cli.INFO, fmt.Sprintf("\tUser GUID: %s", agent.process.UserGUID))
	cli.Message(cli.INFO, fmt.Sprintf("\tIntegrity Level: %d", agent.process.Integrity))
	cli.Message(cli.INFO, fmt.Sprintf("\tIPs: %v", agent.host.IPs))
	cli.Message(cli.DEBUG, "Leaving agent.New function")

	return
}

// Authenticated returns if the Agent is authenticated to the Merlin server or not
func (a *Agent) Authenticated() bool {
	return a.authenticated
}

// Comms returns the embedded Comms structure which contains information about the Agent's communication profile but
// is not the actual client used for network communications
func (a *Agent) Comms() Comms {
	return a.comms
}

// Failed returns the number of times the Agent has failed to successfully check in
func (a *Agent) Failed() int {
	return a.comms.Failed
}

// Host returns the embedded Host structure that contains information about the Host where the Agent is running such as
// the hostname and operating system
func (a *Agent) Host() Host {
	return a.host
}

// ID returns the Agent's unique identifier
func (a *Agent) ID() uuid.UUID {
	return a.id
}

// KillDate returns the date, as an epoch timestamp, that the Agent will quit running
func (a *Agent) KillDate() int64 {
	return a.comms.Kill
}

// MaxRetry returns the configured value for how many times the Agent will try to connect in before it quits running
func (a *Agent) MaxRetry() int {
	return a.comms.Retry
}

// Process returns the embedded Process structure that contains information about the process this Merlin Agent is running in
// such as the process id, username, or integrity level
func (a *Agent) Process() Process {
	return a.process
}

// SetAuthenticated updates the Agent's authentication status
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetAuthenticated(authenticated bool) {
	a.authenticated = authenticated
}

// SetComms updates the Agent's embedded Comms structure with the one provided
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetComms(comms Comms) {
	a.comms = comms
}

// SetFailedCheckIn updates the number of times the Agent has actually failed to check in
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetFailedCheckIn(failed int) {
	a.comms.Failed = failed
}

// SetInitialCheckIn updates the time stamp that the Agent first successfully connected to the Merlin server
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetInitialCheckIn(checkin time.Time) {
	a.initial = checkin
}

// SetKillDate updates the date, as an epoch timestamp, that the Agent will quit running
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetKillDate(epochDate int64) {
	a.comms.Kill = epochDate
}

// SetMaxRetry updates the number of times the Agent can fail to check in before it quits running
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetMaxRetry(retries int) {
	a.comms.Retry = retries
}

// SetSkew updates the amount of jitter or skew added to the Agent's sleep or wait time
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetSkew(skew int64) {
	a.comms.Skew = skew
}

// SetStatusCheckIn updates the last time the Agent successfully communicated with the Merlin server
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetStatusCheckIn(checkin time.Time) {
	a.checkin = checkin
}

// SetWaitTime updates the amount of time the Agent will wait or sleep before it attempts to check in again
// The updated Agent object must be stored or updated in the repository separately for the change to be permanent
func (a *Agent) SetWaitTime(wait time.Duration) {
	a.comms.Wait = wait
}

// Skew returns the amount of jitter or skew the Agent is adding to the amount of time it sleeps between check ins
func (a *Agent) Skew() int64 {
	return a.comms.Skew
}

// Wait returns the amount of time the Agent will wait or sleep between check ins
func (a *Agent) Wait() time.Duration {
	return a.comms.Wait
}
