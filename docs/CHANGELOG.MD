# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 1.0.3 - June XX, 2021

### Added

-  `ifconfig`/`ipconfig`: Prints host network adapter information. Windows hosts use API calls to get extra info (e.g., DHCP) from https://github.com/r00t0v3rr1d3/merlin/commit/42a12af99610e439721cbd095a2d55523e7cbc94

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