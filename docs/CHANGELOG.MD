# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 1.3.1 - 2022-XX-XX

### Fixed

- [Issue 10](https://github.com/Ne0nd0g/merlin-agent/issues/10) - The `shell` command now uses associated impersonation token

## 1.3.0 - 2022-02-17

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