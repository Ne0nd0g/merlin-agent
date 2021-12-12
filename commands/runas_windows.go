// +build windows

// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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

package commands

import (
	// Standard
	"fmt"
	"strings"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin-agent/os/windows/pkg/processes"
)

// RunAs creates a new process as the provided user
func RunAs(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering RunAs() with %+v", cmd))

	// Username, Password, Application, Arguments
	if len(cmd.Args) < 3 {
		results.Stderr = fmt.Sprintf("expected 3+ arguments, recieved %d for RunAs command", len(cmd.Args))
		return
	}

	username := cmd.Args[0]
	password := cmd.Args[1]
	application := cmd.Args[2]
	var arguments string
	if len(cmd.Args) > 3 {
		arguments = strings.Join(cmd.Args[3:], " ")
	}

	results.Stdout, results.Stderr = processes.CreateProcessWithLogon(username, "", password, application, arguments, processes.LOGON_WITH_PROFILE, true)

	return
}
