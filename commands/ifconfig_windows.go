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
*/package commands

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// ifconfig enumerates the network interfaces and their configuration
// Much of this is ripped from interface_windows.go
func ifconfig() (stdout string, err error) {
	fSize := uint32(0)
	b := make([]byte, 1000)

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	var adapterInfo *syscall.IpAdapterInfo
	adapterInfo = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
	err = syscall.GetAdaptersInfo(adapterInfo, &fSize)

	// Call it once to see how much data you need in fSize
	if err == syscall.ERROR_BUFFER_OVERFLOW {
		b := make([]byte, fSize)
		adapterInfo = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
		err = syscall.GetAdaptersInfo(adapterInfo, &fSize)
		if err != nil {
			return "", err
		}
	}

	for _, iface := range ifaces {
		for ainfo := adapterInfo; ainfo != nil; ainfo = ainfo.Next {
			if int(ainfo.Index) == iface.Index {
				stdout += fmt.Sprintf("%s\n", iface.Name)
				stdout += fmt.Sprintf("  MAC Address\t%s\n", iface.HardwareAddr.String())
				ipentry := &ainfo.IpAddressList
				for ; ipentry != nil; ipentry = ipentry.Next {
					stdout += fmt.Sprintf("  IP Address\t%s\n", ipentry.IpAddress.String)
					stdout += fmt.Sprintf("  Subnet Mask\t%s\n", ipentry.IpMask.String)
				}
				gateways := &ainfo.GatewayList
				for ; gateways != nil; gateways = gateways.Next {
					stdout += fmt.Sprintf("  Gateway\t%s\n", gateways.IpAddress.String)
				}

				if ainfo.DhcpEnabled != 0 {
					stdout += fmt.Sprintf("  DHCP\t\tEnabled\n")
					dhcpServers := &ainfo.DhcpServer
					for ; dhcpServers != nil; dhcpServers = dhcpServers.Next {
						stdout += fmt.Sprintf("  DHCP Server:\t%s\n", dhcpServers.IpAddress.String)
					}
				} else {
					stdout += fmt.Sprintf("  DHCP\t\tDisabled\n")
				}
				stdout += "\n"
			}
		}
	}

	return stdout, nil
}
