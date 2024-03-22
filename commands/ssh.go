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
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"

	// X Packages
	"golang.org/x/crypto/ssh"

	// Merlin
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// SSH executes a command on a remote host using the SSH protocol and does not provide an interactive session
func SSH(command jobs.Command) (results jobs.Results) {
	// 1. User, 2. Pass, 3. Host:Port, 4. Command
	if len(command.Args) < 4 {
		results.Stderr = fmt.Sprintf("expected 4 or more arguments, received %d", len(command.Args))
		return
	}

	user := command.Args[0]
	pass := command.Args[1]
	host := command.Args[2]
	cmd := strings.Join(command.Args[3:], " ")

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			results.Stdout = fmt.Sprintf("Connected to %s at %s with public key %s\n", hostname, remote.String(), key.Type()+" "+base64.StdEncoding.EncodeToString(key.Marshal()))
			return nil
		}),
	}

	sshClient, err := ssh.Dial("tcp", host, config)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling ssh.Dial: %s", err)
		return
	}

	defer func() {
		err2 := sshClient.Close()
		if err2 != nil {
			results.Stderr += fmt.Sprintf("there was an error closing the SSH client: %s\n", err2)
		}
	}()

	sshSession, err := sshClient.NewSession()
	if err != nil {
		results.Stderr = fmt.Sprintf("\nthere was an error calling SSH Client NewSession(): %s", err)
		return
	}

	defer func() {
		err2 := sshSession.Close()
		if err2 != nil && err2 != io.EOF {
			results.Stderr = fmt.Sprintf("\nthere was an error closing the SSH session: %s\n", err2)
		}
	}()

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer

	sshSession.Stdout = io.Writer(&stdoutBuffer)
	sshSession.Stderr = io.Writer(&stderrBuffer)

	err = sshSession.Run(cmd)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling SSH Session Run(): %s", err)
		return
	}

	results.Stdout += stdoutBuffer.String()
	results.Stderr = stderrBuffer.String()
	return
}
