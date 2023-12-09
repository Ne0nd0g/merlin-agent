//go:build windows

/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023 Russel Van Tuyl

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

package text

import (
	// Standard
	"bytes"
	"fmt"
	"io"

	// X Packages
	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
)

// DecodeString decodes a byte slice to a string using the current code page
func DecodeString(encoded []byte) (decoded string, err error) {
	codePage := windows.GetACP()

	switch codePage {
	// 437 is the default code page for US English
	case 437:
		decoded = string(encoded)
		return
	// 932 is the default code page for Japanese
	case 932:
		t, e := io.ReadAll(transform.NewReader(bytes.NewReader(encoded), japanese.ShiftJIS.NewDecoder()))
		if e != nil {
			err = fmt.Errorf("os/windows/pkg/text.DecodeString(): there was an error decoding the string to ShiftJIS: %s", e)
			return
		}
		decoded = string(t)
	default:
		decoded = fmt.Sprintf("\n***The output was not valid UTF-8 and there isn't a configured decoder for code page %d***\n\n", codePage)
		decoded += string(bytes.ToValidUTF8(encoded, []byte("�")))
	}
	return
}
