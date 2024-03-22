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
	// standard
	"fmt"
	"syscall"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"

	// Merlin
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-message/jobs"
)

type Process1 interface {
	// Pid is the process ID for this process.
	Pid() int

	// PPid is the parent process ID for this process
	PPid() int

	// Executable name running this process. This is not a path to the executable
	Executable() string

	Owner() string

	Arch() string
}

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	pid   int
	ppid  int
	exe   string
	owner string
	arch  string
}

func (p *WindowsProcess) Pid() int {
	return p.pid
}

func (p *WindowsProcess) PPid() int {
	return p.ppid
}

func (p *WindowsProcess) Executable() string {
	return p.exe
}

func (p *WindowsProcess) Owner() string {
	return p.owner
}

func (p *WindowsProcess) Arch() string {
	return p.arch
}

func newWindowsProcess(e *syscall.ProcessEntry32) *WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}
	account, _ := getProcessOwner(e.ProcessID)

	pHandle, _ := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, e.ProcessID)
	defer syscall.CloseHandle(pHandle)
	isWow64Process, err := IsWow64Process(pHandle)

	arch := "x86"
	if !isWow64Process {
		arch = "x64"
	}
	if err != nil {
		arch = "err"
	}

	return &WindowsProcess{
		pid:   int(e.ProcessID),
		ppid:  int(e.ParentProcessID),
		exe:   syscall.UTF16ToString(e.ExeFile[:end]),
		owner: account,
		arch:  arch,
	}
}

func findProcess(pid int) (Process1, error) {
	ps, err := getProcesses()
	if err != nil {
		return nil, err
	}

	for _, p := range ps {
		if p.Pid() == pid {
			return p, nil
		}
	}

	return nil, nil
}

// getInfo retrieves a specified type of information about an access token.
func getInfo(t syscall.Token, class uint32, initSize int) (unsafe.Pointer, error) {
	n := uint32(initSize)
	for {
		b := make([]byte, n)
		e := syscall.GetTokenInformation(t, class, &b[0], uint32(len(b)), &n)
		if e == nil {
			return unsafe.Pointer(&b[0]), nil
		}
		if e != syscall.ERROR_INSUFFICIENT_BUFFER {
			return nil, e
		}
		if n <= uint32(len(b)) {
			return nil, e
		}
	}
}

// getTokenUser retrieves access token t owner account information.
func getTokenUser(t syscall.Token) (*syscall.Tokenuser, error) {
	i, e := getInfo(t, syscall.TokenUser, 50)
	if e != nil {
		return nil, e
	}
	return (*syscall.Tokenuser)(i), nil
}

func getProcessOwner(pid uint32) (owner string, err error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(handle)
	var token syscall.Token
	if err = syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token); err != nil {
		return
	}
	tokenUser, err := getTokenUser(token)
	if err != nil {
		return
	}
	owner, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	owner = fmt.Sprintf("%s\\%s", domain, owner)
	return
}

// IsWow64Process determines the process architecture
// https://github.com/shenwei356/rush/blob/master/process/process_windows.go
func IsWow64Process(processHandle syscall.Handle) (bool, error) {
	var wow64Process bool
	kernel32 := windows.NewLazySystemDLL("kernel32")
	procIsWow64Process := kernel32.NewProc("IsWow64Process")

	r1, _, e1 := procIsWow64Process.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&wow64Process)))
	if int(r1) == 0 {
		return false, e1
	}
	return wow64Process, nil
}

func getProcesses() ([]Process1, error) {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(handle)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err = syscall.Process32First(handle, &entry); err != nil {
		return nil, err
	}

	results := make([]Process1, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			break
		}
	}

	return results, nil
}

// PS is only a valid function on Windows agents...for now
func PS() jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering PS()..."))
	var results jobs.Results

	// Setup OS environment, if any
	err := Setup()
	if err != nil {
		results.Stderr = err.Error()
		return results
	}
	defer TearDown()

	processList, err := getProcesses()
	if err != nil {
		results.Stderr = fmt.Sprintf("\nthere was an error calling the ps command: %s", err)
		return results
	}

	results.Stdout = fmt.Sprintf("\nPID\tPPID\tARCH\tOWNER\tEXE\n")
	for x := range processList {
		var process Process1
		process = processList[x]
		results.Stdout += fmt.Sprintf("%d\t%d\t%s\t%s\t%s\n", process.Pid(), process.PPid(), process.Arch(), process.Owner(), process.Executable())
	}
	return results
}
