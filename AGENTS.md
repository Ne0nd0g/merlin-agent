# AGENTS.md — merlin-agent

Guidance for AI coding agents working in this repo. Human contributors may find it useful too.

## What this is

The **Merlin agent** (implant). Go module `github.com/Ne0nd0g/merlin-agent/v2`. Connects to a
Merlin server's HTTP listener, authenticates (OPAQUE by default), and runs jobs. It is wrapped by
`merlin-agent-dll` (c-archive/c-shared builds) and shipped by the `merlin-mythic` payload type.

Target Go: **1.27** (revival target; drop the stale `toolchain` directive). Builds clean on Go 1.26.

## Build / run

```bash
go build ./...
go build -o merlinAgent .
GOOS=windows GOARCH=amd64 go build -o agent.exe .     # cross-compile example
```

Run flags (see `main.go` for the full set):

```bash
./merlinAgent -url http://host:port/ -psk merlin -proto http -sleep 1s
```

- `-proto`: `http` (HTTP/1.1 clear), `https` (HTTP/1.1 TLS), `h2` (HTTP/2 TLS), `h2c` (HTTP/2 clear),
  `http3` (QUIC), plus `tcp-/udp-/smb-` bind/reverse for P2P.
- `-secure`: a **string** bool. `InsecureTLS = !secure`; default `"false"` (skips TLS verification).
  Set `-secure true` to require server-cert validation.
- Default PSK is `merlin`; it must match the listener's PSK.

## Security-sensitive / fast-moving dependencies

Prioritize these in upgrades (they also drive the current Dependabot alerts): `golang.org/x/crypto`,
`github.com/quic-go/quic-go`, `github.com/refraction-networking/utls`, `github.com/cloudflare/circl`,
`github.com/klauspost/compress`, `github.com/andybalholm/brotli`, `github.com/go-jose/go-jose/v3`.

## Cross-repo dependencies (release order matters)

```
merlin-message (base, stable v1.3.0) ──> merlin-agent (this repo) ──┬──> merlin-agent-dll
                                                                    └──> merlin-mythic
```

`merlin-message` is imported directly. Changes here ripple into `merlin-agent-dll` (bump its
`merlin-agent/v2` require) and the `merlin-mythic` payload (bump `agent_version`). Verify against the
server with `../merlin/test/smoke/run.sh`.

## Conventions

- **Branches:** do all work on `dev` (or a feature branch). **Never commit to `main`.**
- **Commits:** the maintainer signs every commit with a YubiKey. **Do not run `git commit`** —
  stage changes and propose a commit message. Do **not** add a `Co-Authored-By` trailer.
- Match surrounding style; keep the GPLv3 license header on new Go files.
