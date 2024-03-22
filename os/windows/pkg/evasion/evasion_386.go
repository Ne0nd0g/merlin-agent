//go:build windows && !amd64

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

package evasion

import (
	// Standard
	"fmt"
)

// Patch will find the target procedure and overwrite the start of its function with the provided bytes.
// Used to for evasion to patch things like amsi.dll!AmsiScanBuffer or ntdll.dll!EtwEvenWrite
func Patch(module string, proc string, data *[]byte) (string, error) {
	return "", fmt.Errorf("cannot patch %s!%s on x86 architecture", module, proc)
}

// Read will find the target module and procedure address and then read its byteLength
func Read(module string, proc string, byteLength int) ([]byte, error) {
	return []byte{}, fmt.Errorf("cannot read %d bytes for %s!%s on x86 architecture", byteLength, module, proc)
}

// ReadBanana will find the target procedure and overwrite the start of its function with the provided bytes directly
// using the NtReadVirtualMemory syscall
func ReadBanana(module string, proc string, byteLength int) ([]byte, error) {
	return []byte{}, fmt.Errorf("cannot read %d bytes for %s!%s on x86 architecture", byteLength, module, proc)
}

// Write will find the target module and procedure and overwrite the start of the function with the provided bytes
func Write(module string, proc string, data *[]byte) error {
	return fmt.Errorf("cannot write %d bytes for %s!%s on x86 architecture", len(*data), module, proc)
}

// WriteBanana will find the target module and procedure and overwrite the start of the function with the provided bytes
// using the ZwWriteVirtualMemory syscall directly
func WriteBanana(module string, proc string, data *[]byte) error {
	return fmt.Errorf("cannot write %d bytes for %s!%s on x86 architecture", len(*data), module, proc)
}
