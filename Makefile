# !!!MAKE SURE YOUR GOPATH ENVIRONMENT VARIABLE IS SET FIRST!!!

# Agent file names
W=Windows-x64
L=Linux-x64
B=FreeBSD-x64
A=Linux-arm
M=Linux-mips
D=Darwin-x64

# Merlin version number
VERSION=$(shell cat ./core/core.go |grep "var Version ="|cut -d"\"" -f2)

MAGENT=merlinAgent
PASSWORD=merlin
BUILD=$(shell git rev-parse HEAD)
DIR=bin/v${VERSION}/${BUILD}

# Merlin Agent Variables
XBUILD=-X main.build=${BUILD} -X github.com/Ne0nd0g/merlin-agent/agent.build=${BUILD}
URL ?= https://127.0.0.1:443
XURL=-X main.url=${URL}
PSK ?= merlin
XPSK=-X main.psk=${PSK}
PROXY ?=
XPROXY =-X main.proxy=$(PROXY)
HOST ?=
XHOST =-X main.host=$(HOST)
PROTO ?= h2
XPROTO =-X main.protocol=$(PROTO)
JA3 ?=
XJA3 =-X main.ja3=$(JA3)

# Compile Flags
LDFLAGS=-ldflags "-s -w ${XBUILD} ${XPROTO} ${XURL} ${XHOST} ${XPSK} ${XPROXY} -buildid="
WINAGENTLDFLAGS=-ldflags "-s -w ${XBUILD} ${XPROTO} ${XURL} ${XHOST} ${XPSK} ${XPROXY} -H=windowsgui -buildid="
GCFLAGS=-gcflags=all=-trimpath=$(GOPATH)
ASMFLAGS=-asmflags=all=-trimpath=$(GOPATH)# -asmflags=-trimpath=$(GOPATH)

# Package Command
PACKAGE=7za a -p${PASSWORD} -mhe -mx=9
F=LICENSE

# Make Directory to store executables
$(shell mkdir -p ${DIR})

# Change default to just make for the host OS and add MAKE ALL to do this
default:
	go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT} ./main.go

all: windows linux darwin freebsd

# Compile Agent - Windows x64
windows:
	export GOOS=windows GOARCH=amd64;go build -trimpath ${WINAGENTLDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${W}.exe ./main.go

# Compile Agent - Windows x64 Debug (Can view STDOUT)
windows-debug:
	export GOOS=windows GOARCH=amd64;go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-Debug-${W}.exe ./main.go

# Compile Agent - Linux mips
mips:
	export GOOS=linux;export GOARCH=mips;go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${M} ./main.go

# Compile Agent - Linux arm
arm:
	export GOOS=linux;export GOARCH=arm;export GOARM=7;go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${A} ./main.go

# Compile Agent - Linux x64
linux:
	export GOOS=linux;export GOARCH=amd64;go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${L} ./main.go

# Compile Agent - FreeBSD x64
freebsd:
	export GOOS=freebsd;export GOARCH=amd64;go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${B} ./main.go

# Compile Agent - Darwin x64
darwin:
	export GOOS=darwin;export GOARCH=amd64;go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${D} ./main.go

package-windows:
	${PACKAGE} ${DIR}/${MAGENT}-${W}.7z ${F}
	cd ${DIR};${PACKAGE} ${MAGENT}-${W}.7z ${MAGENT}-${W}.exe

package-linux:
	${PACKAGE} ${DIR}/${MAGENT}-${L}.7z ${F}
	cd ${DIR};${PACKAGE} ${MAGENT}-${L}.7z ${MAGENT}-${L}

package-darwin:
	${PACKAGE} ${DIR}/${MAGENT}-${D}.7z ${F}
	cd ${DIR};${PACKAGE} ${MAGENT}-${D}.7z ${MAGENT}-${D}

package-freebsd:
	${PACKAGE} ${DIR}/${MAGENT}-${B}.7z ${F}
	cd ${DIR};${PACKAGE} ${MAGENT}-${B}.7z ${MAGENT}-${D}

clean:
	rm -rf ${DIR}*

package-all: package-windows package-linux package-darwin package-freebsd

#Build all files for release distribution
distro: clean all package-all
