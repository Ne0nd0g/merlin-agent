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

package advapi32

import (
	// Standard
	"fmt"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"
)

var Advapi32 = windows.NewLazySystemDLL("Advapi32.dll")

// CreateProcessWithLogon Creates a new process and its primary thread.
// Then the new process runs the specified executable file in the security context of the specified credentials
// (user, domain, and password). It can optionally load the user profile for a specified user.
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
func CreateProcessWithLogon(lpUsername *uint16, lpDomain *uint16, lpPassword *uint16, dwLogonFlags uint32, lpApplicationName *uint16, lpCommandLine *uint16, dwCreationFlags uint32, lpEnvironment uintptr, lpCurrentDirectory *uint16, lpStartupInfo *windows.StartupInfo, lpProcessInformation *windows.ProcessInformation) error {
	CreateProcessWithLogonW := Advapi32.NewProc("CreateProcessWithLogonW")

	// Parse optional arguments
	var domain uintptr
	if *lpDomain == 0 {
		domain = 0
	} else {
		domain = uintptr(unsafe.Pointer(lpDomain))
	}

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
	if *lpCurrentDirectory == 0 {
		currentDirectory = 0
	} else {
		currentDirectory = uintptr(unsafe.Pointer(lpCurrentDirectory))
	}

	// BOOL CreateProcessWithLogonW(
	//  [in]                LPCWSTR               lpUsername,
	//  [in, optional]      LPCWSTR               lpDomain,
	//  [in]                LPCWSTR               lpPassword,
	//  [in]                DWORD                 dwLogonFlags,
	//  [in, optional]      LPCWSTR               lpApplicationName, The function does not use the search path
	//  [in, out, optional] LPWSTR                lpCommandLine, The maximum length of this string is 1024 characters.
	//  [in]                DWORD                 dwCreationFlags,
	//  [in, optional]      LPVOID                lpEnvironment,
	//  [in, optional]      LPCWSTR               lpCurrentDirectory,
	//  [in]                LPSTARTUPINFOW        lpStartupInfo,
	//  [out]               LPPROCESS_INFORMATION lpProcessInformation
	//);
	ret, _, err := CreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(lpUsername)),
		domain,
		uintptr(unsafe.Pointer(lpPassword)),
		uintptr(dwLogonFlags),
		applicationName,
		commandLine,
		uintptr(dwCreationFlags),
		lpEnvironment,
		currentDirectory,
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)),
	)
	if err != syscall.Errno(0) || ret == 0 {
		return fmt.Errorf("there was an error calling CreateProcessWithLogon with return code %d: %s", ret, err)
	}
	return nil
}

// CreateProcessWithTokenW creates a new process and its primary thread. The new process runs in the security context of
// the specified token. It can optionally load the user profile for the specified user.
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
func CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation uintptr) (err error) {

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
	ret, _, err := Advapi32.NewProc("CreateProcessWithTokenW").Call(
		hToken,
		dwLogonFlags,
		lpApplicationName,
		lpCommandLine,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
	)
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling advapi32!CreateProcessWithTokenW with return code %d: %s", ret, err)
		return
	}
	return nil
}

// ImpersonateLoggedOnUser lets the calling thread impersonate the security context of a logged-on user.
// The user is represented by a token handle.
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
func ImpersonateLoggedOnUser(hToken windows.Token) (err error) {
	impersonateLoggedOnUser := Advapi32.NewProc("ImpersonateLoggedOnUser")

	// BOOL ImpersonateLoggedOnUser(
	//  [in] HANDLE hToken
	//);
	_, _, err = impersonateLoggedOnUser.Call(uintptr(hToken))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling ImpersonateLoggedOnUser: %s", err)
		return
	}
	err = nil
	return
}

// LogonUser attempts to log a user on to the local computer.
// The local computer is the computer from which LogonUser was called. You cannot use LogonUser to log on to a remote computer.
// You specify the user with a user name and domain and authenticate the user with a plaintext password.
// If the function succeeds, you receive a handle to a token that represents the logged-on user.
// You can then use this token handle to impersonate the specified user or, in most cases, to create a process that runs in the context of the specified user.
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
func LogonUser(lpszUsername *uint16, lpszDomain *uint16, lpszPassword *uint16, dwLogonType uint32, dwLogonProvider uint32) (token *unsafe.Pointer, err error) {
	// The LogonUser function was not available in the golang.org/x/sys/windows package at the time of writing
	LogonUserW := Advapi32.NewProc("LogonUserW")

	// BOOL LogonUserW(
	//  [in]           LPCWSTR lpszUsername,
	//  [in, optional] LPCWSTR lpszDomain,
	//  [in, optional] LPCWSTR lpszPassword,
	//  [in]           DWORD   dwLogonType,
	//  [in]           DWORD   dwLogonProvider,
	//  [out]          PHANDLE phToken
	//);

	var phToken unsafe.Pointer

	_, _, err = LogonUserW.Call(
		uintptr(unsafe.Pointer(lpszUsername)),
		uintptr(unsafe.Pointer(lpszDomain)),
		uintptr(unsafe.Pointer(lpszPassword)),
		uintptr(dwLogonType),
		uintptr(dwLogonProvider),
		uintptr(unsafe.Pointer(&phToken)),
	)
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling advapi32!LogonUserW: %s", err)
		return
	}
	return &phToken, nil
}

// LookupPrivilegeName retrieves the name that corresponds to the privilege represented on a specific system by a
// specified locally unique identifier (LUID).
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew
func LookupPrivilegeName(luid windows.LUID) (privilege string, err error) {
	lookupPrivilegeNameW := Advapi32.NewProc("LookupPrivilegeNameW")

	// BOOL LookupPrivilegeNameW(
	//  [in, optional]  LPCWSTR lpSystemName,
	//  [in]            PLUID   lpLuid,
	//  [out, optional] LPWSTR  lpName,
	//  [in, out]       LPDWORD cchName
	//);

	// Call to determine the size
	var cchName uint32
	ret, _, err := lookupPrivilegeNameW.Call(0, uintptr(unsafe.Pointer(&luid)), 0, uintptr(unsafe.Pointer(&cchName)))
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("there was an error calling advapi32!LookupPrivilegeName for %+v with return code %d: %s", luid, ret, err)
	}

	var lpName uint16
	ret, _, err = lookupPrivilegeNameW.Call(0, uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&lpName)), uintptr(unsafe.Pointer(&cchName)))
	if err != windows.Errno(0) || ret == 0 {
		return "", fmt.Errorf("there was an error calling advapi32!LookupPrivilegeName with return code %d: %s", ret, err)
	}

	return windows.UTF16PtrToString(&lpName), nil
}
