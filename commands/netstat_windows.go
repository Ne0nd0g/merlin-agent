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
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"syscall"
	"unsafe"

	// Merlin
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// Netstat is used to print network connections on the target system
func Netstat(cmd jobs.Command) jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("entering Netstat() with %+v", cmd))
	var results jobs.Results
	var err string
	var actualargument string

	if len(cmd.Args) > 1 {
		actualargument = cmd.Args[1]
	}

	out, err := netstat(actualargument)

	if err != "" {
		results.Stderr = fmt.Sprintf("%s\r\n", err)
	} else {
		results.Stdout = out
	}
	return results
}

// SockAddr represents an ip:port pair
type SockAddr struct {
	IP   net.IP
	Port uint16
}

func (s *SockAddr) String() string {
	return fmt.Sprintf("%v:%d", s.IP, s.Port)
}

// SockTabEntry type represents each line of the /proc/net/[tcp|udp]
type SockTabEntry struct {
	ino        string
	LocalAddr  *SockAddr
	RemoteAddr *SockAddr
	State      SkState
	UID        uint32
	Process    *Process
}

// Process holds the PID and process name to which each socket belongs
type Process struct {
	Pid  int
	Name string
}

func (p *Process) String() string {
	return fmt.Sprintf("%d/%s", p.Pid, p.Name)
}

// SkState type represents socket connection state
type SkState uint8

func (s SkState) String() string {
	return skStates[s]
}

// AcceptFn is used to filter socket entries. The value returned indicates
// whether the element is to be appended to the socket list.
type AcceptFn func(*SockTabEntry) bool

// NoopFilter - a test function returning true for all elements
func NoopFilter(*SockTabEntry) bool { return true }

// TCPSocks returns a slice of active TCP sockets containing only those
// elements that satisfy the accept function
func TCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	return osTCPSocks(accept)
}

// TCP6Socks returns a slice of active TCP IPv4 sockets containing only those
// elements that satisfy the accept function
func TCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return osTCP6Socks(accept)
}

// UDPSocks returns a slice of active UDP sockets containing only those
// elements that satisfy the accept function
func UDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	return osUDPSocks(accept)
}

// UDP6Socks returns a slice of active UDP IPv6 sockets containing only those
// elements that satisfy the accept function
func UDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return osUDP6Socks(accept)
}

const (
	errInsuffBuff = syscall.Errno(122)

	Th32csSnapProcess  = uint32(0x00000002)
	InvalidHandleValue = ^uintptr(0)
	MaxPath            = 260
)

var (
	modiphlpapi = syscall.NewLazyDLL("Iphlpapi.dll")
	modkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procGetTCPTable2        = modiphlpapi.NewProc("GetTcpTable2")
	procGetTCP6Table2       = modiphlpapi.NewProc("GetTcp6Table2")
	procGetExtendedUDPTable = modiphlpapi.NewProc("GetExtendedUdpTable")
	procCreateSnapshot      = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First      = modkernel32.NewProc("Process32First")
	procProcess32Next       = modkernel32.NewProc("Process32Next")
)

// Socket states
const (
	Close       SkState = 0x01
	Listen              = 0x02
	SynSent             = 0x03
	SynRecv             = 0x04
	Established         = 0x05
	FinWait1            = 0x06
	FinWait2            = 0x07
	CloseWait           = 0x08
	Closing             = 0x09
	LastAck             = 0x0a
	TimeWait            = 0x0b
	DeleteTcb           = 0x0c
)

var skStates = [...]string{
	"UNKNOWN",
	"", // CLOSE
	"LISTEN",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"CLOSE_WAIT",
	"CLOSING",
	"LAST_ACK",
	"TIME_WAIT",
	"DELETE_TCB",
}

func memToIPv4(p unsafe.Pointer) net.IP {
	a := (*[net.IPv4len]byte)(p)
	ip := make(net.IP, net.IPv4len)
	copy(ip, a[:])
	return ip
}

func memToIPv6(p unsafe.Pointer) net.IP {
	a := (*[net.IPv6len]byte)(p)
	ip := make(net.IP, net.IPv6len)
	copy(ip, a[:])
	return ip
}

func memtohs(n unsafe.Pointer) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(n)[:])
}

type WinSock struct {
	Addr uint32
	Port uint32
}

func (w *WinSock) Sock() *SockAddr {
	ip := memToIPv4(unsafe.Pointer(&w.Addr))
	port := memtohs(unsafe.Pointer(&w.Port))
	return &SockAddr{IP: ip, Port: port}
}

type WinSock6 struct {
	Addr    [net.IPv6len]byte
	ScopeID uint32
	Port    uint32
}

func (w *WinSock6) Sock() *SockAddr {
	ip := memToIPv6(unsafe.Pointer(&w.Addr[0]))
	port := memtohs(unsafe.Pointer(&w.Port))
	return &SockAddr{IP: ip, Port: port}
}

type MibTCPRow2 struct {
	State      uint32
	LocalAddr  WinSock
	RemoteAddr WinSock
	WinPid
	OffloadState uint32
}

type WinPid uint32

func (pid WinPid) Process(snp ProcessSnapshot) *Process {
	if pid < 1 {
		return nil
	}
	return &Process{
		Pid:  int(pid),
		Name: snp.ProcPIDToName(uint32(pid)),
	}
}

func (m *MibTCPRow2) LocalSock() *SockAddr  { return m.LocalAddr.Sock() }
func (m *MibTCPRow2) RemoteSock() *SockAddr { return m.RemoteAddr.Sock() }
func (m *MibTCPRow2) SockState() SkState    { return SkState(m.State) }

type MibTCPTable2 struct {
	NumEntries uint32
	Table      [1]MibTCPRow2
}

func (t *MibTCPTable2) Rows() []MibTCPRow2 {
	var s []MibTCPRow2
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&t.Table[0]))
	hdr.Len = int(t.NumEntries)
	hdr.Cap = int(t.NumEntries)
	return s
}

// MibTCP6Row2 structure contains information that describes an IPv6 TCP
// connection.
type MibTCP6Row2 struct {
	LocalAddr  WinSock6
	RemoteAddr WinSock6
	State      uint32
	WinPid
	OffloadState uint32
}

func (m *MibTCP6Row2) LocalSock() *SockAddr  { return m.LocalAddr.Sock() }
func (m *MibTCP6Row2) RemoteSock() *SockAddr { return m.RemoteAddr.Sock() }
func (m *MibTCP6Row2) SockState() SkState    { return SkState(m.State) }

// MibTCP6Table2 structure contains a table of IPv6 TCP connections on the
// local computer.
type MibTCP6Table2 struct {
	NumEntries uint32
	Table      [1]MibTCP6Row2
}

func (t *MibTCP6Table2) Rows() []MibTCP6Row2 {
	var s []MibTCP6Row2
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&t.Table[0]))
	hdr.Len = int(t.NumEntries)
	hdr.Cap = int(t.NumEntries)
	return s
}

// MibUDPRowOwnerPID structure contains an entry from the User Datagram
// Protocol (UDP) listener table for IPv4 on the local computer. The entry also
// includes the process ID (PID) that issued the call to the bind function for
// the UDP endpoint
type MibUDPRowOwnerPID struct {
	WinSock
	WinPid
}

func (m *MibUDPRowOwnerPID) LocalSock() *SockAddr  { return m.Sock() }
func (m *MibUDPRowOwnerPID) RemoteSock() *SockAddr { return &SockAddr{net.IPv4zero, 0} }
func (m *MibUDPRowOwnerPID) SockState() SkState    { return Close }

// MibUDPTableOwnerPID structure contains the User Datagram Protocol (UDP)
// listener table for IPv4 on the local computer. The table also includes the
// process ID (PID) that issued the call to the bind function for each UDP
// endpoint.
type MibUDPTableOwnerPID struct {
	NumEntries uint32
	Table      [1]MibUDPRowOwnerPID
}

func (t *MibUDPTableOwnerPID) Rows() []MibUDPRowOwnerPID {
	var s []MibUDPRowOwnerPID
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&t.Table[0]))
	hdr.Len = int(t.NumEntries)
	hdr.Cap = int(t.NumEntries)
	return s
}

// MibUDP6RowOwnerPID serves the same purpose as MibUDPRowOwnerPID, except that
// the information in this case is for IPv6.
type MibUDP6RowOwnerPID struct {
	WinSock6
	WinPid
}

func (m *MibUDP6RowOwnerPID) LocalSock() *SockAddr  { return m.Sock() }
func (m *MibUDP6RowOwnerPID) RemoteSock() *SockAddr { return &SockAddr{net.IPv4zero, 0} }
func (m *MibUDP6RowOwnerPID) SockState() SkState    { return Close }

// MibUDP6TableOwnerPID serves the same purpose as MibUDPTableOwnerPID for IPv6
type MibUDP6TableOwnerPID struct {
	NumEntries uint32
	Table      [1]MibUDP6RowOwnerPID
}

func (t *MibUDP6TableOwnerPID) Rows() []MibUDP6RowOwnerPID {
	var s []MibUDP6RowOwnerPID
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&t.Table[0]))
	hdr.Len = int(t.NumEntries)
	hdr.Cap = int(t.NumEntries)
	return s
}

// Processentry32 describes an entry from a list of the processes residing in
// the system address space when a snapshot was taken
type Processentry32 struct {
	Size                uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PriClassBase        int32
	Flags               uint32
	ExeFile             [MaxPath]byte
}

func rawGetTCPTable2(proc uintptr, tab unsafe.Pointer, size *uint32, order bool) error {
	var oint uintptr
	if order {
		oint = 1
	}
	r1, _, callErr := syscall.Syscall(
		proc,
		uintptr(3),
		uintptr(tab),
		uintptr(unsafe.Pointer(size)),
		oint)
	if callErr != 0 {
		return callErr
	}
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func getTCPTable2(proc uintptr, order bool) ([]byte, error) {
	var (
		size uint32
		buf  []byte
	)

	// determine size
	err := rawGetTCPTable2(proc, unsafe.Pointer(nil), &size, false)
	if err != nil && err != errInsuffBuff {
		return nil, err
	}
	buf = make([]byte, size)
	table := unsafe.Pointer(&buf[0])
	err = rawGetTCPTable2(proc, table, &size, true)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// GetTCPTable2 function retrieves the IPv4 TCP connection table
func GetTCPTable2(order bool) (*MibTCPTable2, error) {
	b, err := getTCPTable2(procGetTCPTable2.Addr(), true)
	if err != nil {
		return nil, err
	}
	return (*MibTCPTable2)(unsafe.Pointer(&b[0])), nil
}

// GetTCP6Table2 function retrieves the IPv6 TCP connection table
func GetTCP6Table2(order bool) (*MibTCP6Table2, error) {
	b, err := getTCPTable2(procGetTCP6Table2.Addr(), true)
	if err != nil {
		return nil, err
	}
	return (*MibTCP6Table2)(unsafe.Pointer(&b[0])), nil
}

// The UDPTableClass enumeration defines the set of values used to indicate
// the type of table returned by calls to GetExtendedUDPTable
type UDPTableClass uint

// Possible table class values
const (
	UDPTableBasic UDPTableClass = iota
	UDPTableOwnerPID
	UDPTableOwnerModule
)

func getExtendedUDPTable(table unsafe.Pointer, size *uint32, order bool, af uint32, cl UDPTableClass) error {
	var oint uintptr
	if order {
		oint = 1
	}
	r1, _, callErr := syscall.Syscall6(
		procGetExtendedUDPTable.Addr(),
		uintptr(6),
		uintptr(table),
		uintptr(unsafe.Pointer(size)),
		oint,
		uintptr(af),
		uintptr(cl),
		uintptr(0))
	if callErr != 0 {
		return callErr
	}
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// GetExtendedUDPTable function retrieves a table that contains a list of UDP
// endpoints available to the application
func GetExtendedUDPTable(order bool, af uint32, cl UDPTableClass) ([]byte, error) {
	var size uint32
	err := getExtendedUDPTable(nil, &size, order, af, cl)
	if err != nil && err != errInsuffBuff {
		return nil, err
	}
	buf := make([]byte, size)
	err = getExtendedUDPTable(unsafe.Pointer(&buf[0]), &size, order, af, cl)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func GetUDPTableOwnerPID(order bool) (*MibUDPTableOwnerPID, error) {
	b, err := GetExtendedUDPTable(true, syscall.AF_INET, UDPTableOwnerPID)
	if err != nil {
		return nil, err
	}
	return (*MibUDPTableOwnerPID)(unsafe.Pointer(&b[0])), nil
}

func GetUDP6TableOwnerPID(order bool) (*MibUDP6TableOwnerPID, error) {
	b, err := GetExtendedUDPTable(true, syscall.AF_INET6, UDPTableOwnerPID)
	if err != nil {
		return nil, err
	}
	return (*MibUDP6TableOwnerPID)(unsafe.Pointer(&b[0])), nil
}

// ProcessSnapshot wraps the syscall.Handle, which represents a snapshot of
// the specified processes.
type ProcessSnapshot syscall.Handle

// CreateToolhelp32Snapshot takes a snapshot of the specified processes, as
// well as the heaps, modules, and threads used by these processes
func CreateToolhelp32Snapshot(flags uint32, pid uint32) (ProcessSnapshot, error) {
	r1, _, callErr := syscall.Syscall(
		procCreateSnapshot.Addr(),
		uintptr(2),
		uintptr(flags),
		uintptr(pid), 0)
	ret := ProcessSnapshot(r1)
	if callErr != 0 {
		return ret, callErr
	}
	if r1 == InvalidHandleValue {
		return ret, fmt.Errorf("invalid handle value: %#v", r1)
	}
	return ret, nil
}

// ProcPIDToName translates PID to a name
func (snp ProcessSnapshot) ProcPIDToName(pid uint32) string {
	var processEntry Processentry32
	processEntry.Size = uint32(unsafe.Sizeof(processEntry))
	handle := syscall.Handle(snp)
	err := Process32First(handle, &processEntry)
	if err != nil {
		return ""
	}
	for {
		if processEntry.Th32ProcessID == pid {
			return StringFromNullTerminated(processEntry.ExeFile[:])
		}
		err = Process32Next(handle, &processEntry)
		if err != nil {
			return ""
		}
	}
}

// Close releases underlying win32 handle
func (snp ProcessSnapshot) Close() error {
	return syscall.CloseHandle(syscall.Handle(snp))
}

// Process32First retrieves information about the first process encountered
// in a system snapshot
func Process32First(handle syscall.Handle, pe *Processentry32) error {
	pe.Size = uint32(unsafe.Sizeof(*pe))
	r1, _, callErr := syscall.Syscall(
		procProcess32First.Addr(),
		uintptr(2),
		uintptr(handle),
		uintptr(unsafe.Pointer(pe)), 0)
	if callErr != 0 {
		return callErr
	}
	if r1 == 0 {
		return nil
	}
	return nil
}

// Process32Next retrieves information about the next process
// recorded in a system snapshot
func Process32Next(handle syscall.Handle, pe *Processentry32) error {
	pe.Size = uint32(unsafe.Sizeof(*pe))
	r1, _, callErr := syscall.Syscall(
		procProcess32Next.Addr(),
		uintptr(2),
		uintptr(handle),
		uintptr(unsafe.Pointer(pe)), 0)
	if callErr != 0 {
		return callErr
	}
	if r1 == 0 {
		return nil
	}
	return nil
}

// StringFromNullTerminated returns a string from a nul-terminated byte slice
func StringFromNullTerminated(b []byte) string {
	n := bytes.IndexByte(b, '\x00')
	if n < 1 {
		return ""
	}
	return string(b[:n])
}

type winSockEnt interface {
	LocalSock() *SockAddr
	RemoteSock() *SockAddr
	SockState() SkState
	Process(snp ProcessSnapshot) *Process
}

func toSockTabEntry(ws winSockEnt, snp ProcessSnapshot) SockTabEntry {
	return SockTabEntry{
		LocalAddr:  ws.LocalSock(),
		RemoteAddr: ws.RemoteSock(),
		State:      ws.SockState(),
		Process:    ws.Process(snp),
	}
}

func osTCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	tbl, err := GetTCPTable2(true)
	if err != nil {
		return nil, err
	}
	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	var sktab []SockTabEntry
	s := tbl.Rows()
	for i := range s {
		ent := toSockTabEntry(&s[i], snp)
		if accept(&ent) {
			sktab = append(sktab, ent)
		}
	}
	snp.Close()
	return sktab, nil
}

func osTCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	tbl, err := GetTCP6Table2(true)
	if err != nil {
		return nil, err
	}
	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	var sktab []SockTabEntry
	s := tbl.Rows()
	for i := range s {
		ent := toSockTabEntry(&s[i], snp)
		if accept(&ent) {
			sktab = append(sktab, ent)
		}
	}
	snp.Close()
	return sktab, nil
}

func osUDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	tbl, err := GetUDPTableOwnerPID(true)
	if err != nil {
		return nil, err
	}
	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	var sktab []SockTabEntry
	s := tbl.Rows()
	for i := range s {
		ent := toSockTabEntry(&s[i], snp)
		if accept(&ent) {
			sktab = append(sktab, ent)
		}
	}
	snp.Close()
	return sktab, nil
}

func osUDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	tbl, err := GetUDP6TableOwnerPID(true)
	if err != nil {
		return nil, err
	}
	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	var sktab []SockTabEntry
	s := tbl.Rows()
	for i := range s {
		ent := toSockTabEntry(&s[i], snp)
		if accept(&ent) {
			sktab = append(sktab, ent)
		}
	}
	snp.Close()
	return sktab, nil
}

const (
	protoIPv4 = 0x01
	protoIPv6 = 0x02
)

// Accepts "udp" or "tcp"
func netstat(filter string) (stdout string, stderr string) {
	var udp bool
	var tcp bool
	switch filter {
	case "udp":
		udp = true
	case "tcp":
		tcp = true
	default:
		udp = true
		tcp = true
	}
	listening := false
	all := true
	ipv4 := true
	ipv6 := true

	var proto uint
	if ipv4 {
		proto |= protoIPv4
	}
	if ipv6 {
		proto |= protoIPv6
	}
	if proto == 0x00 {
		proto = protoIPv4 | protoIPv6
	}

	//if os.Geteuid() != 0 {
	//	stdout += fmt.Sprintf("\nElevated privileges needed to identify all process information\n")
	//}
	stdout += fmt.Sprintf("\nProto %-23s %-23s %-12s %-16s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name")

	if udp {
		if proto&protoIPv4 == protoIPv4 {
			tabs, err := UDPSocks(NoopFilter)
			if err == nil {
				proto := "udp"
				lookup := func(skaddr *SockAddr) string {
					const IPv4Strlen = 17
					addr := skaddr.IP.String()
					if len(addr) > IPv4Strlen {
						addr = addr[:IPv4Strlen]
					}
					return fmt.Sprintf("%s:%d", addr, skaddr.Port)
				}

				for _, e := range tabs {
					p := ""
					if e.Process != nil {
						p = e.Process.String()
					}
					saddr := lookup(e.LocalAddr)
					daddr := lookup(e.RemoteAddr)
					stdout += fmt.Sprintf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
				}
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := UDP6Socks(NoopFilter)
			if err == nil {
				proto := "udp6"
				lookup := func(skaddr *SockAddr) string {
					const IPv4Strlen = 17
					addr := skaddr.IP.String()
					if len(addr) > IPv4Strlen {
						addr = addr[:IPv4Strlen]
					}
					return fmt.Sprintf("%s:%d", addr, skaddr.Port)
				}

				for _, e := range tabs {
					p := ""
					if e.Process != nil {
						p = e.Process.String()
					}
					saddr := lookup(e.LocalAddr)
					daddr := lookup(e.RemoteAddr)
					stdout += fmt.Sprintf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
				}
			}
		}
	} else {
		tcp = true
	}

	if tcp {
		var fn AcceptFn

		switch {
		case all:
			fn = func(*SockTabEntry) bool { return true }
		case listening:
			fn = func(s *SockTabEntry) bool {
				return s.State == Listen
			}
		default:
			fn = func(s *SockTabEntry) bool {
				return s.State != Listen
			}
		}

		if proto&protoIPv4 == protoIPv4 {
			tabs, err := TCPSocks(fn)
			if err == nil {
				proto := "tcp"
				lookup := func(skaddr *SockAddr) string {
					const IPv4Strlen = 17
					addr := skaddr.IP.String()
					if len(addr) > IPv4Strlen {
						addr = addr[:IPv4Strlen]
					}
					return fmt.Sprintf("%s:%d", addr, skaddr.Port)
				}

				for _, e := range tabs {
					p := ""
					if e.Process != nil {
						p = e.Process.String()
					}
					saddr := lookup(e.LocalAddr)
					daddr := lookup(e.RemoteAddr)
					stdout += fmt.Sprintf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
				}
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := TCP6Socks(fn)
			if err == nil {
				proto := "tcp6"
				lookup := func(skaddr *SockAddr) string {
					const IPv4Strlen = 17
					addr := skaddr.IP.String()
					if len(addr) > IPv4Strlen {
						addr = addr[:IPv4Strlen]
					}
					return fmt.Sprintf("%s:%d", addr, skaddr.Port)
				}

				for _, e := range tabs {
					p := ""
					if e.Process != nil {
						p = e.Process.String()
					}
					saddr := lookup(e.LocalAddr)
					daddr := lookup(e.RemoteAddr)
					stdout += fmt.Sprintf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
				}
			}
		}
	}
	return stdout, ""
}
