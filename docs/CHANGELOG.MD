# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 2.4.2 - 2024-10-14

### Fixed

- Fixed [Issue 43](https://github.com/Ne0nd0g/merlin-agent/issues/43) - Added `fmt` import to FreeBSD shell

### Changed

- Check if Mythic client configuration contained a PSK for the Mythic `http` C2 profile
- Upgraded the following libraries:
  - golang.org/x/crypto v0.22.0 => v0.28.0
  - golang.org/x/net v0.24.0 => v0.30.0
  - golang.org/x/sys v0.19.0 => v0.26.0
  - golang.org/x/text v0.14.0 => v0.19.0
  - github.com/fatih/color v1.16.0 => v1.17.0
  - github.com/quic-go/quic-go v0.42.0 => v0.47.0
  - github.com/refraction-networking/utls v1.6.4 => v1.6.7

## 2.4.1 - 2024-04-23

### Changed

- Upgraded golang.org/x/crypto v0.21.0 => v0.22.0
- Upgraded golang.org/x/sys v0.18.0 => v0.19.0
- Upgraded golang.org/x/mod v0.16.0 => v0.17.0
- Upgraded golang.org/x/tools v0.19.0 => v0.20.0
- Upgraded golang.org/x/exp v0.0.0-20240318143956-a85f2c67cd81 => v0.0.0-20240416160154-fe59bbe5cc7f
- Upgraded github.com/google/pprof v0.0.0-20240320155624-b11c3daa6f07 => v0.0.0-20240422182052-72c8669ad3e7
- Upgraded github.com/onsi/ginkgo/v2 v2.17.0 => v2.17.1
- Upgraded github.com/klauspost/compress v1.17.7 => v1.17.8
- Upgraded github.com/refraction-networking/utls v1.6.3 => v1.6.4
- GoVulnCheck to use the latest version of Go

### Security

- [GO-2024-2687](https://pkg.go.dev/vuln/GO-2024-2687) - Upgraded `golang.org/x/net` to v0.24.0 to address CVE-2024-2687

## 2.4.0 - 2024-03-23

### Added

- Mythic client handles multiple HTTP headers with the Mythic `http` C2 Profile
- Automatic Windows HTTP proxy authentication through the `winhttp` API
- Added the `-http-client` command line argument and `HTTPCLIENT` Makefile variable to specify which HTTP client to use
  - Use `go` for the default Go HTTP client
  - Use `winhttp` API for HTTP C2
- Use `go build` tags to control which C2 clients are compiled into the agent. [Build Tags](https://merlin-c2.readthedocs.io/en/latest/agent/custom.html#build-tags)
  - When ANY build tag is included, the agent will ONLY include that feature and nothing else. For example, if ONLY the http tag is provided, the SMB, TCP, and UDP clients will not be included.
  - If one of the following build tags is used, then only the C2 profiles provided will be compiled in
  - `http` - Include all HTTP clients (including HTTP/1.1, HTTP/2, and HTTP/3)
  - `http1` - Include HTTP/1.1 client
  - `http2` - Include HTTP/2 client
  - `http3` - Include HTTP/3 client
  - `winhttp` - Include Windows `winhttp` API client
  - `mythic` - Include the Mythic client for the Mythic `http` C2 profile
  - `smb` - Include SMB client
  - `tcp` - Include TCP client
  - `udp` - Include UDP client

### Fixed

- Resolved several SOCKS5 issues
  - Updated Mythic client to handle `post_response` actions with `ServerPostResponse` structure to include SOCKS information
  - Created a go routine and a channel just for sending SOCKS data in place of using the Jobs channel
- [Issue 38](https://github.com/Ne0nd0g/merlin-agent/issues/38) - Added `evasion_386.go` to facilitate x86 Windows builds 

### Changed

- Upgraded the following libraries to their latest version
  - upgraded golang.org/x/net v0.21.0 => v0.22.0
  - upgraded github.com/google/uuid v1.5.0 => v1.6.0
  - upgraded github.com/quic-go/quic-go v0.40.1 => v0.42.0
  - upgraded github.com/refraction-networking/utls v1.6.0 => v1.6.3

### Security

- Upgraded go-jose/v3 to v3.0.3 to address CVE-2024-28180

## 2.3.0 - 2023-12-26

### Added

- Support to decode Simplified Chinese (Code Page 936) encoding to UTF-8
- Support to decode Traditional Chinese (Code Page 950) encoding to UTF-8
- Support to decode Korean (Code Page 949) encoding to UTF-8
- Added 'RSA' as a valid authentication method for Mythic EKE
- Added 'mythic' encoder to transform messages in the format Mythic expects them in

### Changed

- Refactored clients/mythic to correctly implement the Client interface from merlin-agent/v2 package
  - Moved encryption out of the client and into the transforms
  - Accepts authenticator, transforms, and secure TLS configuration items
- Upgraded:
  - `github.com/Ne0nd0g/merlin-message` to v1.3.0
  - `golang.org/x/net` to v0.19.0
  - `github.com/quic-go/quic-go` to v0.40.1
  - `github.com/refraction-networking/utls` to v1.6.0
- Removed `GOGARBLE` environment variable from Makefile

## 2.2.0 - 2023-12-14

### Added

- New `os/windows/pkg/text` package to detect and handle non UTF-8 encoding
  - Only handles ShiftJIS at this moment
  - Will replace non UTF-8 characters with a � character

### Fixed

- [Issue 33](https://github.com/Ne0nd0g/merlin-agent/issues/33) - Added handling for ShiftJIS encoding

## 2.1.0 - 2023-11-27

### Changed

- Allow the TLS X509 certificate validation setting to be passed through to JA3 and Parrot clients
- JA3 & Parrot HTTP transports use agent's `-secure` command line argument to determine if TLS X.509 certificate validation should be performed
- Upgraded the following modules
  - `golang.org/x/sys v0.13.0 => v0.14.0`
  - `golang.org/x/net v0.17.0 => v0.18.0`
  - `github.com/go-jose/go-jose/v3 v3.0.0 => v3.0.1`
  - `github.com/fatih/color v1.15.0 => v1.16.0`
  
### Fixed

- [Issue 26](https://github.com/Ne0nd0g/merlin-agent/issues/26) - uTLS package uses HTTP proxy if provided or from environment variables
  - Implemented a custom dialer to connect to the proxy first and then the destination
- uTLS package for correctly set the TLS version from the provided JA3 string


## 2.0.0 - 2023-11-03

### Added

- Peer-to-Peer Agent communication methods: smb-bind, smb-reverse, tcp-bind, tcp-reverse, udp-bind, udp-reverse
  - An associated Listener UUID must be provided with `-listener` command line argument or `LISTENER` Make file variable
  - An associated network interface and port must be provided with the `-addr` command line argument or `ADDR` Make file variable
  - `Delegate` message type and associated handling
- Configurable Agent authentication methods: OPAQUE & none
  - Added `auth` variable to main.go
  - Added `AUTH` variable to Make file (e.g., `make windows AUTH=OPAQUE`)
  - Added `-auth` command line argument
- Configurable Agent transforms: gob-base, gob-string, base64-byte, base64-string, hex,-byte, hex-string, aes, jwe, rc4, and xor
  - Added `transforms` variable to main.go
  - Added `TRANSFORMS` variable to Make file (e.g., `make windows TRANSFORMS=aes,gob-base)
  - Added `-transforms` command line argument
- `link` command for the Agent to initiate a peer-to-peer connection with a listening bind agent
  - Example: `link tcp 192.168.1.72:4444`
- `listener` command for the Agent to start a listener to receive a connection from a reverse peer-to-peer connection
  - `list` to return a list of instantiated on the Agent (e.g., `listener list`)
  - `start` to start a listener based on the passed in type and interface
    - Example: `listener start tcp 0.0.0.0:4444`
  - `stop` to stop an already created listener
    - Example: `listener stop tcp [::]:4444`
- `unlink` command to disconnect a chile peer-to-peer agent from its parent
  - Example: `unlink childAgentID`
- GitHub Actions for building and testing the Merlin Agent
- Implemented "services" and "repositories"
  - Services are: agent, client, job, message, and p2p
- Configurable TLS x.509 certificate validation
  - Default is `false`, TLS certificates are not validated
  - Added `-secure` command line argument to require TLS X.509 certificate validation
  - Added `SECURE` variable to Make file (e.g., `make windows SECURE=true`)

### Changed

- Moved from `Initial` to `Authenticated` for Agent struct
- Removed tests
- Upgraded [quic-go](https://github.com/quic-go/quic-go) to v0.40.0
- The Minimum supported Go version is now 1.20
- HTTP URL rotation strategy is now random instead of round-robin
- Replaced `github.com/satori/go.uuid` with `github.com/google/uuid`
- Replaced `github.com/square/go-jose` with `github.com/go-jose/go-jose`
- Replaced `github.com/Ne0nd0g/merlin/pkg/messages` with `github.com/Ne0nd0g/merlin-message`
  - Removes the need to depend on or import the Merlin Server package 

## 1.6.5 - 2023-06-10

### Changed

- Replaced manual Windows DLL and procedure loads for Golang's Windows package and moved remaining to `os/windows/api` directory
- Replaced `PAGE_EXECUTE_READWRITE` with `PAGE_READWRITE` for shellcode memory allocation
- Replaced `PAGE_EXECUTE` with `PAGE_EXECUTE_READ` after shellcode memory allocation

### Fixed

- [Issue 28](https://github.com/Ne0nd0g/merlin-agent/issues/28) - Use Golang's Windows package for API calls where possible

## 1.6.4 - 2023-06-08

### Changed

- Updated the Mythic client to handle the new "download" workflow for Mythic v3.0.0

## 1.6.3 - 2023-03-15

### Fixed

- [Issue 25](https://github.com/Ne0nd0g/merlin-agent/issues/25) - Updated Mythic CheckIn structure's PID to integer

## 1.6.2 - 2023-03-08

### Fixed

- [Issue 22](https://github.com/Ne0nd0g/merlin-agent/issues/22) - Upgraded https://github.com/Ne0nd0g/merlin from v1.5.0 to v1.5.1

### Security

- [PR 23](https://github.com/Ne0nd0g/merlin-agent/pull/23) - Bump golang.org/x/net from 0.1.0 to 0.7.0 by dependabot

## 1.6.1 - 2023-03-01

### Fixed

- [Issue 24](https://github.com/Ne0nd0g/merlin-agent/issues/24) - Adjusted the `shell` function call

## 1.6.0 - 2022-11-11

### Added

- Parrot specific web browsers through [utls](https://github.com/refraction-networking/utls#parroting) library
  - Use the agent's `-parrot` command line argument
  - Use the Makefile's `PARROT=` command line argument
  - Can be changed while the agent is already running
  - Examples include `HelloChrome_102` or `HelloRandomized`
  - [List of available strings](https://github.com/refraction-networking/utls/blob/8e1e65eb22d21c635523a31ec2bcb8730991aaad/u_common.go#L150)
  - If a JA3 string is provided, the parrot string will be ignored

### Changed

- Require Go v1.19
- The agent package `New()` function will only print errors to STDOUT instead of returning an error to ensure execution
- JA3 transports are now generated from clients/utls
- Upgraded go-clr to v1.0.3
- Upgraded quic-go to v0.30.0

### Fixed

- [Issue 20](https://github.com/Ne0nd0g/merlin-agent/issues/20) - Manually get username & group for Windows
- [Issue 21](https://github.com/Ne0nd0g/merlin-agent/issues/21) - Resolved file download re-write error

### Removed

- Removed [ja3transport](https://github.com/Ne0nd0g/ja3transport) module and moved code into clients/utls

## 1.5.0 - 2022-07-22

### Added

- Added new SOCKS5 functionality

### Changed

- Go v1.18 is now the minimum supported version
- Upgraded [quic-go](https://github.com/lucas-clemente/quic-go/) to v0.28.0
- Upgraded [Go JOSE](https://github.com/square/go-jose) to v2.6.0
- The `Send()` of the `ClientInterface` interface returns a list of messages.Base instead of a single message
- Initial checkin immediately responds to first AgentInfo request after authenticating instead of after sleep time

### Fixed

- [Issue 17](https://github.com/Ne0nd0g/merlin-agent/issues/17) - Ensure process structure pointer is not nil

## 1.4.2 - 2022-05-03

### Fixed

- [Issue 9](https://github.com/Ne0nd0g/merlin-agent/issues/9) - Replaced `TokenGroup` with `TokenUser`
- [Issue 14](https://github.com/Ne0nd0g/merlin-agent/issues/14) - Let writer close channel and don't try to close STDIN
- [Issue 16](https://github.com/Ne0nd0g/merlin-agent/issues/16) - Handle `jobs.Results` & `jobs.AgentInfo` in `jobsHandler()`

## 1.4.1 - 2022-04-12

### Added

- Go build tags to separate out Mythic client from standalone HTTP1/2/3 client
- Added `SLEEP` to Make file (e.g., `make windows SLEEP=2m`)

### Fixed

- [Issue 13](https://github.com/Ne0nd0g/merlin-agent/issues/13) - Added byte slice variable as a workaround

### Changed

- Upgraded [quic-go](https://github.com/lucas-clemente/quic-go/) to v0.27.0 for Go 1.18 support

## 1.4.0 - 2022-04-02

### Added

- Added a new `memory` command for Windows agents to read/write memory 
  - Uses direct syscalls for `NtReadVirtualMemory`, `NtProtectVirtualMemory`, & `ZwWriteVirtualMemory` implemented using [BananaPhone](https://github.com/C-Sto/BananaPhone)
  - The commands take module name (e.g., `ntdll.dll`) and a procedure name (e.g., `EtwEventWrite`) to target read/write operations
  - The `read` command will just read the specified number of bytes and return the results
  - The `write` command will just write the specified bytes without reading them first
  - The `patch` command will find a specified function, read the existing bytes, and then overwrite it with the provided bytes
- Added `AmsiScanBuffer` patch when loading assemblies into the agent process through the `load-assembly` command

### Changed

- Upgraded go-clr package to tagged version 1.0.2

## 1.3.1 - 2022-03-22

### Added

- Added [Garble](https://github.com/burrowers/garble) builds to the Make file
  - `windows-garble`, `linux-garble`, & `darwin-garble`
  - **THE SERVER MUST BE GARBLED WITH THE EXACT SAME SEED**
  - Specify the seed at build with `make windows-debug SEED=<your seed valuee>`
- Added `GetProcessWindowStation` and `GetThreadDesktop` functions in the `user32` package

### Changed

- Renamed the `SendMerlinMessage` function of the `ClientInterface` to just `Send()`
- Modified `CreateProcessWithToken` function in the `windows/os/pkg/tokens` package to adjust the caller's station and
  desktop DACLs if the token user belongs to a different session

### Fixed

- [Issue 10](https://github.com/Ne0nd0g/merlin-agent/issues/10) - The `shell` command now uses associated impersonation token
- [Issue 11](https://github.com/Ne0nd0g/merlin-agent/issues/11) - The token is now passed along with execution
- [Issue 12](https://github.com/Ne0nd0g/merlin-agent/issues/12) - If running as `NT AUTHORITY\SYSTEM` with an 
impersonation token, Call [LogonUserW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
 and then [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) 
 instead of [CreateProcessWithLogon](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)
 with Merlin's `runas` command

## 1.3 - 2022-02-17

### Changed

- Added the `Integrity` field to the Agent structure
- Added message padding to the following Mythic messages types for the Mythic client:
  - CheckIn
  - Tasking
  - PostResponse
  - RSARequest
  - PostResponseFile
  - PostResponseDownload

### Added

- Added `os.GetIntegrityLevel()` to enumerate the agent's integrity level or elevated status
  - Windows: `2`-Medium, `3`-High, `4`-System
  - All other OS: `3` - member of sudo group, `4` - running as root
- Added a random amount of message padding, up to the padding max value, to HTTP post requests for the Mythic client

## 1.2.1 - 2022-01-10

### Fixed

- [Issue 6](https://github.com/Ne0nd0g/merlin-agent/issues/6) - Message padding is now a random length instead of a fixed length
- [Issue 7](https://github.com/Ne0nd0g/merlin-agent/issues/6) - Windows Access Token now persists between commands

## 1.2.0 - 2021-12-12

### Added

- `rm` command to remove, or delete, files using native Go functions
- `runas` Windows command to create a process as another user with their password
- `ssh` Connect to a remote host over SSH and execute a command (non-interactive)
- `token` Windows command to interact with Windows Access Tokens
  - `make` Create a new token with a username and password; Unlisted `make_token` alias
  - `privs` List the current or remote process token privileges
  - `rev2self` Drop any created or stolen access token and revert to original configuration; Unlisted `rev2self` alias
  - `steal` Steal a token from another process; Unlisted `steal_token` alias
  - `whoami` Enumerate process and thread token username, logon ID, privilege count, token type, impersonation level, and integrity level
- New `os/windows/api` directory for operating system specific API and system calls
- New `os/windows/pkg` directory for functions that wrap operating system specific calls
- Added `commands/os` with `Setup()` and `TearDown()` functions to prep and release process space before executing any commands
  - Due to how the Go runtime works, stolen/created Windows access token must be applied/released for each run of a command
- Add both a `-headers` command line argument and `HEADERS=` Make parameter to add arbitrary HTTP headers
  - The flag takes in a new-line seperated (e.g., `\n`) list of headers
- FreeBSD Makefile build support from [paullj1](https://github.com/paullj1) in [Pull 3](https://github.com/Ne0nd0g/merlin-agent/pull/3)
- Read STDIN for 500 milliseconds for agent argument from [paullj1](https://github.com/paullj1) in [Pull 3](https://github.com/Ne0nd0g/merlin-agent/pull/3)

### Changed

- Broke the `commands/transfer.go` file into `commands/download.go` and `commands/upload.go`
- The `ls` command can now handle Windows UNC paths
- The `run`, `shell`, `execute-assembly`, `execute-pe`, & `execute-shellcode` commands will use the Windows CreateProcessWithTokenW function call if a token was stolen/created
- Updated [go-quic](https://github.com/lucas-clemente/quic-go/) library to v0.24.0

### Fixed

- [Issue 117](https://github.com/Ne0nd0g/merlin/issues/117) - Added random padding to OPAQUE messages

## 1.1.0 - August 4, 2021

### Added

- Incorporated a lot of changes by [r00t0v3rr1d3](https://github.com/r00t0v3rr1d3) & [deviousbanana](https://github.com/deviousbanana) from their [fork](https://github.com/r00t0v3rr1d3/merlin/tree/dev)
- `ifconfig`/`ipconfig`: Prints host network adapter information. Windows hosts use API calls to get extra info (e.g., DHCP) from https://github.com/r00t0v3rr1d3/merlin/commit/42a12af99610e439721cbd095a2d55523e7cbc94
- Agent and AgentInfo structs contain `Process` name from https://github.com/r00t0v3rr1d3/merlin/commit/cbf875427123e6a58a528d0e38a692c2308f09c9
- Added the `kill` command to kill a running process by its process ID (PID)
- Provide a comma seperated list of URLs that Merlin will rotate through for each POST request
  - Example `-url https://127.0.0.1/news.php,https://127.0.0.1/admin/get.php`
- When using http or https protocol, the connection only appears in netstat for one second or less
- Added `sdelete` command to securely delete a file
- Added `touch`, alias is `timestomp`, command that matches the destination file's timestamps with source file
- Added `ps` command that returns a process listing for Windows agents
- Added `netstat` that displays network connection for Windows agents (tcp, tcp6, udp, udp6)
- Added Windows only `pipes` command to list named pipes
- Added Windows only `uptime` command to print the target system's uptime
- Added `env` command: View and modify environment variables. "set" will create a new variable if it didn't exist
  * Usage: `env showall`
  * Usage: `env get PATH`
  * Usage: `env set CUSTOM "my desired value"`
  * Usage: `env unset HISTFILE`

### Changed

- The command used to instruct the agent to quit running is now `exit`
- The Merlin agent Client structure, URL structure, now takes a slice of URLs as a string as opposed to just 1 string

## 1.0.2 - June 25, 2021

### Added

- Use HTTP_PROXY, HTTPS_PROXY & NO_PROXY environment variables if a proxy was not explicitly provided

### Fixed

- Incorrectly used `https` for [TLS ALPN Protocol ID](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids)

## 1.0.1 - May 29, 2021

### Fixed

- [Issue 1](https://github.com/Ne0nd0g/merlin-agent/issues/1) - Added `job.Token` for Minidump command response message

### Added

- `windows-debug` build to Make file; Removes hidden window attribute to view STDOUT/STDERR when troubleshooting

## 1.0.0 - April 17, 2021

- Initial commit
- Moved agent code from github.com/Ne0nd0g/merlin/pkg/agent