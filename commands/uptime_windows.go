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
	"time"

	// Sub Repositories
	"golang.org/x/sys/windows"

	// Merlin
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// Uptime uses the Windows API to get the host's uptime
func Uptime() jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering Uptime()"))
	var results jobs.Results

	kernel32 := windows.NewLazySystemDLL("kernel32")
	GetTicketCount64 := kernel32.NewProc("GetTickCount64")

	r1, _, err := GetTicketCount64.Call(0, 0, 0, 0)

	if err.Error() != "The operation completed successfully." {
		results.Stderr = fmt.Sprintf("\nA call to kernel32.GetTickCount64 in the uptime command returned an error:\n%s", err)
	} else {
		results.Stdout = fmt.Sprintf("\nSystem uptime: %s\n", (time.Duration(r1) * time.Millisecond))
	}
	return results
}
