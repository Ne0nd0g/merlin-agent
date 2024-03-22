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

package kernel32

import (
	// Standard
	"fmt"

	// X Packages
	"golang.org/x/sys/windows"
)

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")

// CreateRemoteThreadEx Creates a thread that runs in the virtual address space of another process and optionally
// specifies extended attributes such as processor group affinity.
// HANDLE CreateRemoteThreadEx(
//
//	[in]            HANDLE                       hProcess,
//	[in, optional]  LPSECURITY_ATTRIBUTES        lpThreadAttributes,
//	[in]            SIZE_T                       dwStackSize,
//	[in]            LPTHREAD_START_ROUTINE       lpStartAddress,
//	[in, optional]  LPVOID                       lpParameter,
//	[in]            DWORD                        dwCreationFlags,
//	[in, optional]  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
//	[out, optional] LPDWORD                      lpThreadId
//
// );
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex
func CreateRemoteThreadEx(hProcess uintptr, lpThreadAttributes uintptr, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags int, lpAttributeList uintptr, lpThreadId uintptr) (addr uintptr, err error) {
	createRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	addr, _, err = createRemoteThreadEx.Call(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, uintptr(dwCreationFlags), lpAttributeList, lpThreadId)
	if err != windows.Errno(0) {
		err = fmt.Errorf("there was an error calling Windows API CreateRemoteThread: %s", err)
	} else {
		err = nil
	}
	return
}

// QueueUserAPC Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread.
// DWORD QueueUserAPC(
//
//	[in] PAPCFUNC  pfnAPC,
//	[in] HANDLE    hThread,
//	[in] ULONG_PTR dwData
//
// );
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
func QueueUserAPC(pfnAPC uintptr, hThread uintptr, dwData uintptr) (err error) {
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	_, _, err = queueUserAPC.Call(pfnAPC, hThread, dwData)
	if err != windows.Errno(0) {
		err = fmt.Errorf("there was an error calling Windows API QueueUserAPC: %s", err)
	} else {
		err = nil
	}
	return
}

// VirtualAllocEx Reserves, commits, or changes the state of a region of memory within the virtual address space of a
// specified process. The function initializes the memory it allocates to zero.
//
//	LPVOID VirtualAllocEx(
//	  [in]           HANDLE hProcess,
//	  [in, optional] LPVOID lpAddress,
//	  [in]           SIZE_T dwSize,
//	  [in]           DWORD  flAllocationType,
//	  [in]           DWORD  flProtect
//	);
//
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
func VirtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize int, flAllocationType int, flProtect int) (addr uintptr, err error) {
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	addr, _, err = virtualAllocEx.Call(hProcess, lpAddress, uintptr(dwSize), uintptr(flAllocationType), uintptr(flProtect))
	if err != windows.Errno(0) {
		err = fmt.Errorf("there was an error calling Windows API VirtualAllocEx: %s", err)
	} else {
		err = nil
	}
	return
}
