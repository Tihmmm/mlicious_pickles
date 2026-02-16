// Package events defines the event types shared between the eBPF programs in kernel space and the Go userspace.
// Struct layouts must exactly match the C definitions in internal/bpf/c/scanner.c
package events

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	MaxFilenameLen = 256
	MaxArgLen      = 128
	MaxArgs        = 4
)

// EventType identifies the kind of syscall event captured by eBPF
type EventType uint32

const (
	EventExecve   EventType = 1
	EventOpenat   EventType = 2
	EventConnect  EventType = 3
	EventSocket   EventType = 4
	EventWrite    EventType = 5
	EventUnlinkat EventType = 6
	EventClone    EventType = 7
)

func (t EventType) String() string {
	switch t {
	case EventExecve:
		return "execve"
	case EventOpenat:
		return "openat"
	case EventConnect:
		return "connect"
	case EventSocket:
		return "socket"
	case EventWrite:
		return "write"
	case EventUnlinkat:
		return "unlinkat"
	case EventClone:
		return "clone"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// Header is present at the start of every event. Matches struct event_header
type Header struct {
	PID         uint32
	TID         uint32
	TimestampNs uint64
	Type        EventType
	_           uint32 // padding
}

// ExecveEvent corresponds to struct execve_event in the BPF program
type ExecveEvent struct {
	Header   Header
	Filename [MaxFilenameLen]byte
	Argv     [MaxArgs][MaxArgLen]byte
	Argc     uint32
	_        uint32
}

// OpenatEvent corresponds to struct openat_event
type OpenatEvent struct {
	Header   Header
	Filename [MaxFilenameLen]byte
	DirFD    int32
	Flags    uint32
}

// ConnectEvent corresponds to struct connect_event
type ConnectEvent struct {
	Header     Header
	AddrFamily uint16
	Port       uint16
	AddrV4     uint32
	AddrV6     [16]byte
}

// SocketEvent corresponds to struct socket_event
type SocketEvent struct {
	Header   Header
	Domain   uint32
	Type     uint32
	Protocol uint32
	_        uint32
}

// WriteEvent corresponds to struct write_event
type WriteEvent struct {
	Header Header
	FD     uint32
	_      uint32
	Count  uint64
}

// UnlinkatEvent corresponds to struct unlinkat_event
type UnlinkatEvent struct {
	Header   Header
	Filename [MaxFilenameLen]byte
	DirFD    int32
	Flags    uint32
}

// CloneEvent corresponds to struct clone_event
type CloneEvent struct {
	Header     Header
	CloneFlags uint64
	ChildPID   uint32
	_          uint32
}

// Helpers

// CStr extracts a NUL-terminated C string from a fixed-size byte array
func CStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// GetFilename returns the filename from an ExecveEvent
func (e *ExecveEvent) GetFilename() string { return CStr(e.Filename[:]) }

// GetArgs returns the argument list from an ExecveEvent
func (e *ExecveEvent) GetArgs() []string {
	args := make([]string, 0, e.Argc)
	for i := uint32(0); i < e.Argc && i < MaxArgs; i++ {
		args = append(args, CStr(e.Argv[i][:]))
	}
	return args
}

// GetFilename returns the filename from an OpenatEvent
func (e *OpenatEvent) GetFilename() string { return CStr(e.Filename[:]) }

// GetFilename returns the filename from an UnlinkatEvent
func (e *UnlinkatEvent) GetFilename() string { return CStr(e.Filename[:]) }

// IP returns the remote IP address from a ConnectEvent
func (e *ConnectEvent) IP() net.IP {
	switch e.AddrFamily {
	case 2: // AF_INET
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, e.AddrV4)
		return ip
	case 10: // AF_INET6
		return e.AddrV6[:]
	default:
		return nil
	}
}

// PortNumber returns the port in host byte order
func (e *ConnectEvent) PortNumber() uint16 {
	return binary.BigEndian.Uint16([]byte{byte(e.Port >> 8), byte(e.Port)})
}
