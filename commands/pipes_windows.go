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

	// Sub Repositories
	"golang.org/x/sys/windows"

	// Merlin
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// Pipes enumerates and returns a list of named pipes for Windows hosts only
func Pipes() jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering Pipes()..."))
	var results jobs.Results
	var err string

	out, err := getPipes()
	if err != "" {
		results.Stderr = fmt.Sprintf("%s\r\n", err)
	} else {
		results.Stdout = out
	}
	return results
}

// Print out the comments of \\.\pipe\*
// Ripped straight out of the Wireguard implementation: conn_windows.go
func getPipes() (stdout string, stderr string) {
	// pipePrefix is the path for windows named pipes
	var pipePrefix = `\\.\pipe\`
	var (
		data windows.Win32finddata
	)

	h, err := windows.FindFirstFile(
		// Append * to find all named pipes.
		windows.StringToUTF16Ptr(pipePrefix+"*"),
		&data,
	)
	if err != nil {
		return "", err.Error()
	}

	// FindClose is used to close file search handles instead of the typical
	// CloseHandle used elsewhere, see:
	// https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-findclose.
	defer windows.FindClose(h)

	stdout = "\nNamed pipes:\n"
	for {
		name := windows.UTF16ToString(data.FileName[:])
		stdout += pipePrefix + name + "\n"

		if err := windows.FindNextFile(h, &data); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}

			return "", err.Error()
		}
	}

	return stdout, ""
}
