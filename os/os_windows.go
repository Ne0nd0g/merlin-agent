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

package os

import (
	// X Packages
	"golang.org/x/sys/windows"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/tokens"
)

// GetIntegrityLevel returns the agent's current Windows Access Token integrity level
// Returns 2 for medium integrity, 3 for high integrity, and 4 for system integrity
// https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
func GetIntegrityLevel() (integrity int, err error) {
	var token windows.Token
	if tokens.Token != 0 {
		token = tokens.Token
	} else {
		token = windows.GetCurrentProcessToken()
	}

	level, err := tokens.GetTokenIntegrityLevel(token)
	if err != nil {
		return
	}

	switch level {
	case "Untrusted":
		integrity = 0
	case "Low":
		integrity = 1
	case "Medium", "Medium High":
		integrity = 2
	case "High":
		integrity = 3
	case "System":
		integrity = 4
	}
	return
}

// GetUser enumerates the username and their primary group for the account running the agent process
// It is OK if this function returns empty strings because we want the agent to run regardless
func GetUser() (username, group string, err error) {
	return tokens.GetCurrentUserAndGroup()
}
