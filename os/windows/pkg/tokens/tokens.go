// +build windows

// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package tokens

import (
	// Standard
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/os/windows/api/advapi32"
	"github.com/Ne0nd0g/merlin-agent/os/windows/pkg/pipes"
)

// CreateProcessWithToken creates a new process as the user associated with the passed in token
// STDOUT/STDERR is redirected to an anonymous pipe and collected after execution to be returned
// This requires administrative privileges or at least the SE_IMPERSONATE_NAME privilege
func CreateProcessWithToken(hToken windows.Token, application string, args []string) (stdout string, stderr string) {
	if application == "" {
		stderr = "a program must be provided for the CreateProcessWithToken call"
		return
	}

	priv := "SeImpersonatePrivilege"
	name, err := syscall.UTF16PtrFromString(priv)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the privilege \"%s\" to LPCWSTR: %s", priv, err)
	}

	// Verify that the calling process has the SE_IMPERSONATE_NAME privilege
	var systemName uint16
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(&systemName, name, &luid)
	if err != nil {
		stderr = err.Error()
		return
	}

	hasPriv, err := hasPrivilege(windows.GetCurrentProcessToken(), luid)
	if err != nil {
		stderr = "the provided access token does not have the SeImpersonatePrivilege and can't be used to create a process"
		return
	}

	// TODO try to enable the priv before returning with an error
	if !hasPriv {
		stderr = "the provided access token does not have the SeImpersonatePrivilege and therefore can't be used to call CreateProcessWithToken"
		return
	}

	// TODO verify the provided token is a PRIMARY token
	// TODO verify the provided token has the TOKEN_QUERY, TOKEN_DUPLICATE, and TOKEN_ASSIGN_PRIMARY access rights

	// Convert the program to a LPCWSTR
	lpApplicationName, err := syscall.UTF16PtrFromString(application)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the application name \"%s\" to LPCWSTR: %s", application, err)
		return
	}

	// Convert the program to a LPCWSTR
	arguments := strings.Join(args, " ")
	lpCommandLine, err := syscall.UTF16PtrFromString(arguments)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the application arguments \"%s\" to LPCWSTR: %s", args, err)
		return
	}

	// Setup pipes to retrieve output
	stdInRead, _, stdOutRead, stdOutWrite, stdErrRead, stdErrWrite, err := pipes.CreateAnonymousPipes()
	if err != nil {
		stderr = err.Error()
		return
	}

	var lpCurrentDirectory uint16 = 0
	lpStartupInfo := &windows.StartupInfo{
		StdInput:   stdInRead,
		StdOutput:  stdOutWrite,
		StdErr:     stdErrWrite,
		Flags:      windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE,
	}
	lpProcessInformation := &windows.ProcessInformation{}
	LOGON_NETCREDENTIALS_ONLY := uint32(0x2) // Could not find this constant in the windows package
	dwLogonFlags := LOGON_NETCREDENTIALS_ONLY
	dwCreationFlags := 0
	var lpEnvironment uintptr

	// Parse optional arguments
	var applicationName uintptr
	if *lpApplicationName == 0 {
		applicationName = 0
	} else {
		applicationName = uintptr(unsafe.Pointer(lpApplicationName))
	}

	var commandLine uintptr
	if *lpCommandLine == 0 {
		commandLine = 0
	} else {
		commandLine = uintptr(unsafe.Pointer(lpCommandLine))
	}

	var currentDirectory uintptr
	if lpCurrentDirectory == 0 {
		currentDirectory = 0
	} else {
		currentDirectory = uintptr(unsafe.Pointer(&lpCurrentDirectory))
	}

	err = advapi32.CreateProcessWithTokenW(
		uintptr(hToken),
		uintptr(dwLogonFlags),
		applicationName,
		commandLine,
		uintptr(dwCreationFlags),
		lpEnvironment,
		//uintptr(unsafe.Pointer(lpCurrentDirectory)),
		currentDirectory,
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)),
	)
	if err != nil {
		stderr = err.Error()
		return
	}

	stdout += fmt.Sprintf("Created proccess with an ID of %d\n", lpProcessInformation.ProcessId)

	// Close the "write" pipe handles
	err = pipes.ClosePipes(0, 0, 0, stdOutWrite, 0, stdErrWrite)
	if err != nil {
		stderr = err.Error()
		return
	}

	// Read from the pipes
	_, out, stderr, err := pipes.ReadPipes(0, stdOutRead, stdErrRead)
	if err != nil {
		stderr += err.Error()
	}
	stdout += out

	// Close the "read" pipe handles
	err = pipes.ClosePipes(stdInRead, 0, stdOutRead, 0, stdErrRead, 0)
	if err != nil {
		stderr += err.Error()
		return
	}

	return
}

// hasPrivilege checks the provided access token to see if it contains the provided privilege
func hasPrivilege(token windows.Token, privilege windows.LUID) (has bool, err error) {
	// Get the privileges and attributes
	// Call to get structure size
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &returnedLen)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		err = fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	// Call again to get the actual structure
	info := bytes.NewBuffer(make([]byte, returnedLen))
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, &info.Bytes()[0], returnedLen, &returnedLen)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	var privilegeCount uint32
	err = binary.Read(info, binary.LittleEndian, &privilegeCount)
	if err != nil {
		err = fmt.Errorf("there was an error reading TokenPrivileges bytes to privilegeCount: %s", err)
		return
	}

	// Read in the LUID and Attributes
	var privs []windows.LUIDAndAttributes
	for i := 1; i <= int(privilegeCount); i++ {
		var priv windows.LUIDAndAttributes
		err = binary.Read(info, binary.LittleEndian, &priv)
		if err != nil {
			err = fmt.Errorf("there was an error reading LUIDAttributes to bytes: %s", err)
			return
		}
		privs = append(privs, priv)
	}

	// Iterate over provided token's privileges and return true if it is present
	for _, priv := range privs {
		if priv.Luid == privilege {
			return true, nil
		}
	}
	return false, nil
}
