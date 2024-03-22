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
	"fmt"
	"net"
)

// ifconfig enumerates the network interfaces and their configuration
func ifconfig() (stdout string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range ifaces {
		stdout += fmt.Sprintf("%s\n", i.Name)
		stdout += fmt.Sprintf("  MAC Address\t%s\n", i.HardwareAddr.String())
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		for _, a := range addrs {
			stdout += fmt.Sprintf("  IP Address\t%s\n", a.String())
		}
	}
	return stdout, nil
}
