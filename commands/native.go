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
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// Merlin Main
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// Native executes a golang native command that does not use any executables on the host
func Native(cmd jobs.Command) jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("Entering into commands.Native() with %+v...", cmd))
	var results jobs.Results

	cli.Message(cli.NOTE, fmt.Sprintf("Executing native command: %s", cmd.Command))

	switch cmd.Command {
	// TODO create a function for each Native Command that returns a string and error and DOES NOT use (a *Agent)

	case "cd":
		// Setup OS environment, if any
		err := Setup()
		if err != nil {
			results.Stderr = err.Error()
			break
		}
		// Defer TearDown and return any errors
		defer func() {
			err = TearDown()
			if err != nil {
				results.Stderr += fmt.Sprintf("there was an error tearing down the OS environment when executing the 'cd' command: %s", err)
			}
		}()
		err = os.Chdir(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing directories when executing the 'cd' command:\r\n%s", err.Error())
		} else {
			path, pathErr := os.Getwd()
			if pathErr != nil {
				results.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'cd' command:\r\n%s", pathErr.Error())
			} else {
				results.Stdout = fmt.Sprintf("Changed working directory to %s", path)
			}
		}
	case "env":
		results.Stdout, results.Stderr = env(cmd.Args)
	case "ls":
		listing, err := list(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing the 'ls' command:\r\n%s", err.Error())
			break
		}
		results.Stdout = listing
	case "ifconfig":
		ifaces, err := ifconfig()
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing the 'ifconfig' command:\n%s", err)
		}
		results.Stdout = ifaces
	case "killprocess":
		results.Stdout, results.Stderr = killProcess(cmd.Args[0])
	case "nslookup":
		results.Stdout, results.Stderr = nslookup(cmd.Args)
	case "pwd":
		dir, err := os.Getwd()
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'pwd' command:\r\n%s", err.Error())
		} else {
			results.Stdout = fmt.Sprintf("Current working directory: %s", dir)
		}
	case "rm":
		if len(cmd.Args) > 0 {
			results.Stdout, results.Stderr = rm(cmd.Args[0])
		} else {
			results.Stderr = "not enough arguments provided to the 'rm' command"
		}
	case "sdelete":
		if len(cmd.Args) > 0 {
			results.Stdout, results.Stderr = sdelete(cmd.Args[0])
		} else {
			results.Stderr = "the sdelete command requires one argument but received 0"
		}
	case "touch":
		if len(cmd.Args) > 1 {
			results.Stdout, results.Stderr = touch(cmd.Args[0], cmd.Args[1])
		} else {
			results.Stderr = fmt.Sprintf("the touch command requires two arguments but received %d", len(cmd.Args))
		}
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid NativeCMD type", cmd.Command)
	}

	if results.Stderr == "" {
		if results.Stdout != "" {
			cli.Message(cli.SUCCESS, results.Stdout)
		}
	} else {
		cli.Message(cli.WARN, results.Stderr)
	}
	return results
}

// list gets and returns a list of files and directories from the input file path
func list(path string) (details string, err error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for list command function: %s", path))
	cli.Message(cli.SUCCESS, fmt.Sprintf("listing directory contents for: %s", path))

	var aPath string
	// UNC Path
	if strings.HasPrefix(path, "\\\\") {
		aPath = path
	} else {
		// Resolve a relative path to absolute
		aPath, err = filepath.Abs(path)
		if err != nil {
			return "", err
		}
	}

	// Setup OS environment, if any
	err = Setup()
	if err != nil {
		return
	}
	// Defer TearDown and return any errors
	defer func() {
		err2 := TearDown()
		if err2 != nil {
			if err != nil {
				err = fmt.Errorf("there were multiple errors. 1. %s 2. %s", err, err2)
			} else {
				err = err2
			}
		}
	}()

	directories, err := os.ReadDir(aPath)
	if err != nil {
		return
	}

	details += fmt.Sprintf("Directory listing for: %s\r\n\r\n", aPath)

	for _, dir := range directories {
		var f os.FileInfo
		f, err = dir.Info()
		if err != nil {
			details += fmt.Sprintf("\nthere was an error getting file info for directory '%s'\n", dir)
		}
		perms := f.Mode().String()
		size := strconv.FormatInt(f.Size(), 10)
		modTime := f.ModTime().String()[0:19]
		name := f.Name()
		details = details + perms + "\t" + modTime + "\t" + size + "\t" + name + "\n"
	}
	return
}

// nslookup is used to perform a DNS query using the host's configured resolver
func nslookup(query []string) (string, string) {
	var resp string
	var stderr string
	for _, q := range query {
		ip := net.ParseIP(q)
		if ip != nil {
			r, err := net.LookupAddr(ip.String())
			if err != nil {
				stderr += fmt.Sprintf("there was an error calling the net.LookupAddr function for %s:\r\n%s", q, err)
			}
			resp += fmt.Sprintf("Query: %s, Result: %s\r\n", q, strings.Join(r, " "))
		} else {
			r, err := net.LookupHost(q)
			if err != nil {
				stderr += fmt.Sprintf("there was an error calling the net.LookupHost function for %s:\r\n%s", q, err)
			}
			resp += fmt.Sprintf("Query: %s, Result: %s\r\n", q, strings.Join(r, " "))
		}
	}
	return resp, stderr
}

// killProcess is used to kill a running process by its number identifier
func killProcess(pid string) (stdout string, stderr string) {

	targetpid, err := strconv.Atoi(pid)
	if err != nil || targetpid < 0 {
		stderr = fmt.Sprintf("There was an error converting the pid %s to an integer:\n%s", pid, err)
		return
	}

	if targetpid < 0 {
		stderr = fmt.Sprintf("The provided pid %d is less than zero and invalid", targetpid)
		return
	}

	// Setup OS environment, if any
	err = Setup()
	if err != nil {
		stderr = err.Error()
		return
	}
	// Defer TearDown and return any errors
	defer func() {
		err = TearDown()
		if err != nil {
			stderr += fmt.Sprintf("there was an error tearing down the OS environment when executing the 'killprocess' command: %s", err)
		}
	}()

	proc, err := os.FindProcess(targetpid)
	if err != nil { // On linux, always returns a process. Don't worry, the Kill() will fail
		stderr = fmt.Sprintf("Could not find a process with pid %d:\r\n%s", targetpid, err)
		return
	}

	err = proc.Kill()
	if err != nil {
		stderr = fmt.Sprintf("Error killing pid %d:\r\n%s", targetpid, err)
		return
	}

	stdout = fmt.Sprintf("Successfully killed pid %d", targetpid)
	return
}

// rm removes, or deletes, a file
func rm(path string) (stdout, stderr string) {
	cli.Message(cli.DEBUG, "Entering into native.rm()... function")

	// Setup OS environment, if any
	err := Setup()
	if err != nil {
		stderr = err.Error()
		return
	}
	// Defer TearDown and return any errors
	defer func() {
		err = TearDown()
		if err != nil {
			stderr += fmt.Sprintf("there was an error tearing down the OS environment when executing the 'rm' command: %s", err)
		}
	}()

	// Verify that file exists
	_, err = os.Stat(path)
	if err != nil {
		stderr = fmt.Sprintf("there was an error executing the 'rm' command: %s", err.Error())
		return
	}

	err = os.Remove(path)
	if err != nil {
		stderr = fmt.Sprintf("there was an error executing the 'rm' command: %s", err.Error())
	}

	stdout = fmt.Sprintf("successfully removed file %s", path)
	return
}

// sdelete securely deletes a file
func sdelete(targetfile string) (resp string, stderr string) {
	targetfile = filepath.Clean(targetfile)

	// Setup OS environment, if any
	err := Setup()
	if err != nil {
		stderr = err.Error()
		return
	}
	// Defer TearDown and return any errors
	defer func() {
		err = TearDown()
		if err != nil {
			stderr += fmt.Sprintf("there was an error tearing down the OS environment when executing the 'sdelete' command: %s", err)
		}
	}()

	// make sure we open the file with correct permission
	// otherwise we will get the bad file descriptor error
	// #nosec G304 operators should be able to specify arbitrary file path
	// #nosec G302 want to use these permissions to ensure access
	file, err := os.OpenFile(targetfile, os.O_RDWR, 0666)

	if err != nil {
		stderr = fmt.Sprintf("Error opening file: %s\r\n%s", targetfile, err.Error())
		return resp, stderr
	}

	// find out how large is the target file
	fileInfo, err := file.Stat()

	if err != nil {
		stderr = fmt.Sprintf("Error determining file size: %s\r\n%s", targetfile, err.Error())
		return resp, stderr
	}

	// calculate the new slice size
	// based on how large our target file is
	var fileSize = fileInfo.Size()
	const fileChunk = 1 * (1 << 20) //1MB Chunks

	// calculate total number of parts the file will be chunked into
	totalPartsNum := uint64(math.Ceil(float64(fileSize) / float64(fileChunk)))

	lastPosition := 0

	for i := uint64(0); i < totalPartsNum; i++ {
		partSize := int(math.Min(fileChunk, float64(fileSize-int64(i*fileChunk))))
		partZeroBytes := make([]byte, partSize)

		// fill out the part with zero value
		copy(partZeroBytes[:], "0")

		// overwrite every byte in the chunk with 0
		n, err := file.WriteAt(partZeroBytes, int64(lastPosition))

		if err != nil {
			stderr = fmt.Sprintf("Error over writing file: %s\r\n%s", targetfile, err.Error())
			return resp, stderr
		}

		resp += fmt.Sprintf("Wiped %v bytes.\n", n)

		// update last written position
		lastPosition = lastPosition + partSize
	}

	err = file.Close()
	if err != nil {
		stderr = fmt.Sprintf("There was an error closing the %s file:\n%s", targetfile, err)
		return
	}

	// finally, remove/delete our file
	err = os.Remove(targetfile)
	if err != nil {
		stderr = fmt.Sprintf("Error deleting file: %s\r\n%s", targetfile, err.Error())
		return resp, stderr
	}
	resp += fmt.Sprintf("Securely deleted file: %s\n", targetfile)

	return resp, stderr

}

// touch matches the destination file's timestamps with source file
func touch(inputsourcefile string, inputdestinationfile string) (resp string, stderr string) {
	sourcefilename := inputsourcefile
	destinationfilename := inputdestinationfile

	// Setup OS environment, if any
	err := Setup()
	if err != nil {
		return "", err.Error()
	}
	// Defer TearDown and return any errors
	defer func() {
		err = TearDown()
		if err != nil {
			stderr += fmt.Sprintf("there was an error tearing down the OS environment when executing the 'touch' command: %s", err)
		}
	}()

	// get last modified time of source file
	sourcefile, err1 := os.Stat(sourcefilename)

	if err1 != nil {
		stderr = fmt.Sprintf("Error retrieving last modified time of: %s\n%s\n", sourcefilename, err1.Error())
		return resp, stderr
	}

	modifiedtime := sourcefile.ModTime()

	// change both atime and mtime to last modified time of source file
	err2 := os.Chtimes(destinationfilename, modifiedtime, modifiedtime)

	if err2 != nil {
		stderr = fmt.Sprintf("Error changing last modified and accessed time of: %s\n%s\n", destinationfilename, err2.Error())
		return resp, stderr
	}
	resp = fmt.Sprintf("File: %s\nLast modified and accessed time set to: %s\n", destinationfilename, modifiedtime)
	return resp, stderr
}
