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

import "time"

type Repository interface {
	// Add stores the Merlin Agent structure to the repository
	Add(agent Agent)
	// Get returns the stored Agent structure
	Get() Agent
	// SetAuthenticated updates the Agent's authentication status and stores the updated Agent in the repository
	SetAuthenticated(authenticated bool)
	// SetComms updates the Agent's embedded Comms structure with the one provided and stores the updated Agent in the repository
	SetComms(comms Comms)
	// SetFailedCheckIn updates the number of times the Agent has actually failed to check in and stores the updated Agent
	// in the repository
	SetFailedCheckIn(failed int)
	// SetInitialCheckIn updates the time stamp that the Agent first successfully connected to the Merlin server and stores
	// the updated Agent in the repository
	SetInitialCheckIn(checkin time.Time)
	// SetKillDate sets the date, as an epoch timestamp, of when the Agent will quit running and stores the updated Agent
	// in the repository
	SetKillDate(epochDate int64)
	// SetMaxRetry updates the number of times the Agent can fail to check in before it quits running and stores the updated
	// Agent in the repository
	SetMaxRetry(retries int)
	// SetSkew updates the amount of jitter or skew added to the Agent's sleep or wait time and stores the updated Agent in
	// the repository
	SetSkew(skew int64)
	// SetSleep updates the amount of time the Agent will wait or sleep before it attempts to check in again and stores the
	// updated Agent in the repository
	SetSleep(sleep time.Duration)
	// SetStatusCheckIn updates the last time the Agent successfully communicated with the Merlin server and stores the
	// updated Agent in the repository
	SetStatusCheckIn(checkin time.Time)
}
