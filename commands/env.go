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
	"os"
	"strings"

	// Merlin
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// env is used to view or modify a host's environment variables
func env(Args []string) (resp string, stderr string) {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering ENV() with args: %+v...", Args))
	if len(Args) > 0 {
		switch strings.ToLower(Args[0]) {
		case "get":
			if len(Args) < 2 {
				stderr = fmt.Sprintf("not enough arguments for the env get command: %+v", Args)
				return
			}
			resp = fmt.Sprintf("\nEnvironment variable %s=%s", Args[1], os.Getenv(Args[1]))
		case "set":
			if len(Args) < 3 {
				stderr = fmt.Sprintf("not enough arguments for the env set command: %+v", Args)
				return
			}
			err := os.Setenv(Args[1], Args[2])
			if err != nil {
				stderr = fmt.Sprintf("there was an error setting the %s environment variable:\n%s", Args[1], err)
				return
			}
			resp = fmt.Sprintf("\nSet environment variable: %s=%s", Args[1], Args[2])
		case "showall":
			resp += "\nEnvironment variables:\n"
			for _, element := range os.Environ() {
				resp += fmt.Sprintf("%s\n", element)
			}
		case "unset":
			if len(Args) < 2 {
				stderr = fmt.Sprintf("not enough arguments for the env unset command: %+v", Args)
				return
			}
			err := os.Unsetenv(Args[1])
			if err != nil {
				stderr = fmt.Sprintf("there was an error unsetting the %s environment variable:\n%s", Args[1], err)
				return
			}
			resp = fmt.Sprintf("\nUnset environment variable: %s", Args[1])
		default:
			stderr = fmt.Sprintf("Invlalid env command: %s", Args[0])
		}
		return
	}
	stderr = "an argument was not provided to the env command"
	return
}
