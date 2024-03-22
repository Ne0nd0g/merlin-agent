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

package os

import (
	"os/user"
)

// GetIntegrityLevel determines if the agent is running in an elevated context such as root
// Returns 4 for root and 3 for members of the sudo group
func GetIntegrityLevel() (integrity int, err error) {
	u, err := user.Current()
	if err != nil {
		return
	}
	if u.Uid == "0" || u.Gid == "0" {
		// 3 represents Windows high-integrity
		// 4 represents Windows system-integrity
		return 4, nil
	}

	// Lookup sudo group number
	sudo, err := user.LookupGroup("sudo")
	if err != nil {
		return
	}

	groups, err := u.GroupIds()
	if err != nil {
		return
	}

	for _, g := range groups {
		if g == sudo.Gid {
			return 3, nil
		}
	}
	return
}

// GetUser enumerates the username and their primary group for the account running the agent process
// It is OK if this function returns empty strings because we want the agent to run regardless
func GetUser() (username, group string, err error) {
	var u *user.User
	u, err = user.Current()
	if err != nil {
		return
	}
	username = u.Username
	group = u.Gid
	return
}
