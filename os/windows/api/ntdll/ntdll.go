//go:build windows
// +build windows

// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

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

package ntdll

import (
	// Standard
	"fmt"

	// X Packages
	"golang.org/x/sys/windows"
)

var ntdll = windows.NewLazySystemDLL("ntdll.dll")

// RtlCopyMemory routine copies the contents of a source memory block to a destination memory block
// void RtlCopyMemory(
//
//	void*       Destination,
//	const void* Source,
//	size_t      Length
//
// );
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory
func RtlCopyMemory(dest uintptr, src uintptr, len uint32) (err error) {
	rtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	_, _, err = rtlCopyMemory.Call(dest, src, uintptr(len))
	if err != windows.Errno(0) {
		err = fmt.Errorf("there was an error calling Windows RtlCopyMemory function: %s", err)
	} else {
		err = nil
	}
	return
}

// RtlCreateUserThread
//
//	NTSTATUS
//	RtlCreateUserThread(
//		IN HANDLE Process,
//		IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
//		IN BOOLEAN CreateSuspended,
//		IN ULONG ZeroBits OPTIONAL,
//		IN SIZE_T MaximumStackSize OPTIONAL,
//		IN SIZE_T CommittedStackSize OPTIONAL,
//		IN PUSER_THREAD_START_ROUTINE StartAddress,
//		IN PVOID Parameter OPTIONAL,
//		OUT PHANDLE Thread OPTIONAL,
//		OUT PCLIENT_ID ClientId OPTIONAL
//	);
//
// https://doxygen.reactos.org/da/d0c/sdk_2lib_2rtl_2thread_8c.html#ae5f514e4fcb7d47880171175e88aa205
func RtlCreateUserThread(hProcess uintptr, lpSecurityDescriptor, bSuspended, zeroBits, maxStack, commitSize, lpStartAddress, pParam, hThread, pClient uintptr) (addr uintptr, err error) {
	rtlCreateUserThread := ntdll.NewProc("RtlCreateUserThread")
	addr, _, err = rtlCreateUserThread.Call(hProcess, lpSecurityDescriptor, bSuspended, zeroBits, maxStack, commitSize, lpStartAddress, pParam, hThread, pClient)
	if err != windows.Errno(0) {
		err = fmt.Errorf("there was an error calling Windows RtlCreateUserThread function: %s", err)
	} else {
		err = nil
	}
	return
}
