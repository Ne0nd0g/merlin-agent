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

// Package socks handles SOCKS5 messages from the server
package socks

import (
	// Standard
	"bytes"
	"fmt"
	"net"
	"sync"

	// 3rd Party
	"github.com/armon/go-socks5"
	"github.com/google/uuid"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-message/jobs"
)

var server *socks5.Server
var connections = sync.Map{}
var done = sync.Map{}

// Handler is the entry point for SOCKS connections.
// This function starts a SOCKS server and processes incoming SOCKS connections
func Handler(msg jobs.Job, jobsOut *chan jobs.Job) {
	//fmt.Printf("socks.Handler(): Received SOCKS job ID: %s, Index: %d, Close: %t, Data Length: %d\n", msg.Payload.(jobs.Socks).ID, msg.Payload.(jobs.Socks).Index, msg.Payload.(jobs.Socks).Close, len(msg.Payload.(jobs.Socks).Data))
	//defer fmt.Printf("\tsocks.Handler(): Exiting ID: %s, Index: %d, Close: %t, Data Length: %d\n", msg.Payload.(jobs.Socks).ID, msg.Payload.(jobs.Socks).Index, msg.Payload.(jobs.Socks).Close, len(msg.Payload.(jobs.Socks).Data))
	job := msg.Payload.(jobs.Socks)

	// See if the SOCKS server has already been created
	if server == nil {
		err := newSOCKSServer()
		if err != nil {
			cli.Message(cli.WARN, err.Error())
			return
		}
	}

	// See if this connection is new
	_, ok := connections.Load(job.ID)
	if !ok && !job.Close {
		client, target := net.Pipe()
		in := make(chan jobs.Socks, 100)
		connection := Connection{
			Job:     msg,
			In:      client,
			Out:     target,
			JobChan: jobsOut,
			in:      &in,
		}
		connections.Store(job.ID, &connection)
		done.Store(job.ID, false)

		// Start the go routine to send read data in and send it to the SOCKS server
		go start(job.ID)
		go listen(job.ID)
		go send(job.ID)
	}

	conn, ok := connections.Load(job.ID)
	if !ok {
		cli.Message(cli.WARN, fmt.Sprintf("connection ID %s was not found", job.ID))
		return
	}
	*conn.(*Connection).in <- job
}

// newSOCKSServer is a factory to create and return a global SOCKS5 server instance
func newSOCKSServer() (err error) {
	cli.Message(cli.NOTE, "Starting SOCKS5 server")
	// Create SOCKS5 server
	conf := &socks5.Config{}
	server, err = socks5.New(conf)
	if err != nil {
		return fmt.Errorf("there was an error creating a new SOCKS5 server: %s", err)
	}
	return
}

// start the SOCKS server to serve the connection
func start(id uuid.UUID) {
	cli.Message(cli.NOTE, fmt.Sprintf("Serving new SOCKS connection ID %s", id))

	connection, ok := connections.Load(id)
	if !ok {
		cli.Message(cli.WARN, fmt.Sprintf("connection %s not found", id))
		return
	}

	err := server.ServeConn(connection.(*Connection).In)
	if err != nil {
		cli.Message(cli.WARN, fmt.Sprintf("there was an error serving SOCKS connection %s: %s", id, err))
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("Finished serving SOCKS connection ID %s", id))
}

// listen continuously for data being returned from the SOCKS server to be sent to the agent
func listen(id uuid.UUID) {
	// Listen for data on the agent-side write pipe
	connection, ok := connections.Load(id)
	if !ok {
		cli.Message(cli.WARN, fmt.Sprintf("connection %s not found", id))
		return
	}

	j := connection.(*Connection).Job
	job := jobs.Job{
		AgentID: j.AgentID,
		ID:      j.ID,
		Token:   j.Token,
		Type:    jobs.SOCKS,
	}

	var i int
	// Loop 1 - SOCKS client version/method request
	// Loop 2 - SOCKS client request
	// Loop 3 - Client data

	for {
		data := make([]byte, 500000)

		n, err := connection.(*Connection).Out.Read(data)
		cli.Message(cli.DEBUG, fmt.Sprintf("Read %d bytes from the OUTBOUND pipe with error %s", n, err))
		//fmt.Printf("[+] Read %d bytes from the OUTBOUND pipe %s with error %s, Data: %x\n", n, id, err, data[:n])
		// Check to see if we closed the connection because we are done with it
		fin, good := done.Load(id)
		if !good {
			cli.Message(cli.WARN, fmt.Sprintf("could not find connection ID %s's done map", id))
		}

		if fin.(bool) {
			done.Delete(id)
			return
		}

		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("there was an error reading from the OUTBOUND pipe: %s", err))
			//fmt.Printf("ERROR reading %d bytes for ID: %s, Index: %d, Close: %t, Data Length: %d, Error: %s\n", n, id, i, j.Payload.(jobs.Socks).Close, len(j.Payload.(jobs.Socks).Data), err)
			return
		}

		// Return data to the client
		job.Payload = jobs.Socks{
			ID:    id,
			Index: i,
			Data:  data[:n],
		}
		*connection.(*Connection).JobChan <- job
		i++
	}
}

// send continuously sends data to the SOCKS server from the SOCKS client
func send(id uuid.UUID) {
	conn, ok := connections.Load(id)
	if !ok {
		cli.Message(cli.WARN, fmt.Sprintf("connection ID %s was not found", id))
		return
	}

	for {
		// Get SOCKS job from the channel
		job := <-*conn.(*Connection).in

		// Check to ensure the index is correct, if not, return it to the channel to be processed again
		if conn.(*Connection).Count != job.Index {
			*conn.(*Connection).in <- job
			continue
		}

		// If there is data, write it to the SOCKS server
		// Send data, if any, before closing the connection
		if len(job.Data) > 0 {
			conn.(*Connection).Count++
			// Write the received data to the agent side pipe
			var buff bytes.Buffer
			_, err := buff.Write(job.Data)
			if err != nil {
				cli.Message(cli.WARN, fmt.Sprintf("there was an error writing SOCKS data to the buffer: %s", err))
				return
			}

			//fmt.Printf("Writing %d bytes to SOCKS target \n", len(job.Data))
			n, err := conn.(*Connection).Out.Write(buff.Bytes())
			if err != nil {
				cli.Message(cli.WARN, fmt.Sprintf("there was an error writing data to the SOCKS %s OUTBOUND pipe: %s", job.ID, err))
				return
			}
			cli.Message(cli.DEBUG, fmt.Sprintf("Wrote %d bytes to the SOCKS %s OUTBOUND pipe with error %s", n, job.ID, err))
		}

		// If the SOCKS client has sent io.EOF to close the connection
		if job.Close {
			// Mythic is sending two Close messages so the counter needs to increment on close too
			if len(job.Data) <= 0 {
				conn.(*Connection).Count++
			}
			cli.Message(cli.NOTE, fmt.Sprintf("Closing SOCKS connection %s", job.ID))

			cli.Message(cli.DEBUG, fmt.Sprintf("Closing SOCKS connection %s OUTBOUND pipe", job.ID))
			err := conn.(*Connection).Out.Close()
			if err != nil {
				cli.Message(cli.WARN, fmt.Sprintf("there was an error closing the SOCKS connection %s OUTBOUND pipe: %s", job.ID, err))
			}

			cli.Message(cli.DEBUG, fmt.Sprintf("Closing SOCKS connection %s INBOUND pipe", job.ID))
			err = conn.(*Connection).In.Close()
			if err != nil {
				cli.Message(cli.WARN, fmt.Sprintf("there was an error closing the SOCKS connection %s INBOUND pipe: %s", job.ID, err))
			}

			// Remove the connection from the map
			connections.Delete(job.ID)
			done.Store(job.ID, true)
			return
		}
	}
}

// Connection is a structure used to track new SOCKS client connections
type Connection struct {
	Job     jobs.Job
	In      net.Conn
	Out     net.Conn
	JobChan *chan jobs.Job   // Channel to send jobs back to the server
	in      *chan jobs.Socks // Channel to receive and process SOCKS data locally
	Count   int              // Counter to track the number of SOCKS messages sent
}
