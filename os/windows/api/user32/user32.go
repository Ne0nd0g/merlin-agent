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

package user32

import (
	// Standard
	"fmt"
	"syscall"

	// X Packages
	"golang.org/x/sys/windows"
)

var User32 = windows.NewLazySystemDLL("User32.dll")

// GetProcessWindowStation Retrieves a handle to the current window station for the calling process.
// If the function succeeds, the return value is a handle to the window station
// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getprocesswindowstation
func GetProcessWindowStation() (hWinsta uintptr, err error) {
	GetProcessWindowStation := User32.NewProc("GetProcessWindowStation")

	hWinsta, _, err = GetProcessWindowStation.Call()

	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling GetProcessWindowsStation: %s", err)
	} else {
		err = nil
	}
	return
}

// GetThreadDesktop Retrieves a handle to the desktop assigned to the specified thread.
// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getthreaddesktop
func GetThreadDesktop(threadID uint32) (hDesktop uintptr, err error) {
	GetThreadDesktop := User32.NewProc("GetThreadDesktop")

	hDesktop, _, err = GetThreadDesktop.Call(uintptr(threadID))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling GetThreadDesktop: %s", err)
	} else {
		err = nil
	}
	return
}
