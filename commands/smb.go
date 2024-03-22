//go:build !windows

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
	"runtime"

	// Merlin
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// This smb.go file is part of the "link" command and is not a standalone command

// ConnectSMB establishes an SMB connection over a named pipe to a smb-bind peer-to-peer Agent
func ConnectSMB(host, pipe string) (results jobs.Results) {
	results.Stderr = fmt.Sprintf("commands/smb.ConnectSMB(): this function is not supported by the %s operating system", runtime.GOOS)
	return
}

// ListenSMB binds to the provided named pipe and listens for incoming SMB connections
func ListenSMB(pipe string) error {
	return fmt.Errorf("commands/smb.ListenSMB(): this function is not supported by the %s operating system", runtime.GOOS)
}
