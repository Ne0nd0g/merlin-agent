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

package processes

import (
	// Standard
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	// X Packages
	"golang.org/x/sys/windows"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/api/advapi32"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/pipes"
)

// LOGON_ The logon option
const (
	LOGON_WITH_PROFILE        uint32 = 0x1
	LOGON_NETCREDENTIALS_ONLY uint32 = 0x2
)

// CreateProcessWithLogon creates a new process and its primary thread. Then the new process runs the specified
// executable file in the security context of the specified credentials (user, domain, and password).
// It can optionally load the user profile for a specified user.
// This wrapper function performs validation checks on input arguments and converts them to the necessary type
func CreateProcessWithLogon(username string, domain string, password string, application string, args string, logon uint32, hide bool) (stdout string, stderr string) {
	if username == "" {
		stderr = "a username must be provided for the CreateProcessWithLogon call"
		return
	}

	if password == "" {
		stderr = "a password must be provided for the CreateProcessWithLogon call"
		return
	}

	if application == "" {
		stderr = "an application must be provided for the CreateProcessWithLogon call"
		return
	}

	// Check for UPN format (e.g., rastley@acme.com)
	if strings.Contains(username, "@") {
		temp := strings.Split(username, "@")
		username = temp[0]
		domain = temp[1]
	}

	// Check for domain format (e.g., ACME\rastley)
	if strings.Contains(username, "\\") {
		temp := strings.Split(username, "\\")
		username = temp[1]
		domain = temp[0]
	}

	// Check for an empty or missing domain; used with local user accounts
	if domain == "" {
		domain = "."
	}

	// Convert the username to a LPCWSTR
	lpUsername, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the username \"%s\" to LPCWSTR: %s", username, err)
		return
	}

	// Convert the domain to a LPCWSTR
	lpDomain, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the domain \"%s\" to LPCWSTR: %s", domain, err)
		return
	}

	// Convert the password to a LPCWSTR
	lpPassword, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the password \"%s\" to LPCWSTR: %s", password, err)
		return
	}

	// Search PATH environment variable to retrieve the application's absolute path
	application, err = exec.LookPath(application)
	if err != nil {
		stderr = fmt.Sprintf("there was an error resolving the absolute path for %s: %s", application, err)
		return
	}

	// Convert the application to a LPCWSTR
	lpApplicationName, err := syscall.UTF16PtrFromString(application)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the application name \"%s\" to LPCWSTR: %s", application, err)
		return
	}

	// Convert the program to a LPCWSTR
	lpCommandLine, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the application arguments \"%s\" to LPCWSTR: %s", args, err)
		return
	}

	// Setup pipes to retrieve output
	stdInRead, _, stdOutRead, stdOutWrite, stdErrRead, stdErrWrite, err := pipes.CreateAnonymousPipes()
	if err != nil {
		stderr = fmt.Sprintf("there was an error creating anonymous pipes to collect output: %s", err)
		return
	}

	lpCurrentDirectory := uint16(0)
	lpStartupInfo := windows.StartupInfo{
		StdInput:  stdInRead,
		StdOutput: stdOutWrite,
		StdErr:    stdErrWrite,
		Flags:     windows.STARTF_USESTDHANDLES,
	}
	if hide {
		lpStartupInfo.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
		lpStartupInfo.ShowWindow = windows.SW_HIDE
	}
	lpProcessInformation := windows.ProcessInformation{}

	err = advapi32.CreateProcessWithLogon(
		lpUsername,
		lpDomain,
		lpPassword,
		logon,
		lpApplicationName,
		lpCommandLine,
		0,
		0,
		&lpCurrentDirectory,
		&lpStartupInfo,
		&lpProcessInformation,
	)

	if err != nil {
		stderr += err.Error()
		return
	}

	stdout += fmt.Sprintf("Created %s process with an ID of %d\n", application, lpProcessInformation.ProcessId)

	// Close the "write" pipe handles
	err = pipes.ClosePipes(0, 0, 0, stdOutWrite, 0, stdErrWrite)
	if err != nil {
		stderr = err.Error()
		return
	}

	// Read from the pipes
	var out string
	_, out, stderr, err = pipes.ReadPipes(0, stdOutRead, stdErrRead)
	if err != nil {
		stderr += err.Error()
		return
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
