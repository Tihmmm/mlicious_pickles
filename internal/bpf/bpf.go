// Package bpf handles loading and attaching eBPF programs for the pickle scanner.
package bpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -target amd64 Scanner ./c/scanner.c -- -I./headers

// Loader manages the lifecycle of eBPF programs and maps
type Loader struct {
	objs   ScannerObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// Load loads the compiled eBPF objects into the kernel
func Load() (*Loader, error) {
	var objs ScannerObjects
	if err := LoadScannerObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}
	return &Loader{objs: objs}, nil
}

// Attach attaches all tracepoint programs and returns a ring buffer reader
func (l *Loader) Attach() (*ringbuf.Reader, error) {
	type prog struct {
		group string
		name  string
		prog  *ebpf.Program
	}

	progs := []prog{
		{"syscalls", "sys_enter_execve", l.objs.TracepointSysEnterExecve},
		{"syscalls", "sys_enter_openat", l.objs.TracepointSysEnterOpenat},
		{"syscalls", "sys_enter_connect", l.objs.TracepointSysEnterConnect},
		{"syscalls", "sys_enter_socket", l.objs.TracepointSysEnterSocket},
		{"syscalls", "sys_enter_write", l.objs.TracepointSysEnterWrite},
		{"syscalls", "sys_enter_unlinkat", l.objs.TracepointSysEnterUnlinkat},
		{"syscalls", "sys_enter_clone", l.objs.TracepointSysEnterClone},
		{"sched", "sched_process_fork", l.objs.TracepointSchedProcessFork},
		{"sched", "sched_process_exit", l.objs.TracepointSchedProcessExit},
	}

	for _, p := range progs {
		lnk, err := link.Tracepoint(p.group, p.name, p.prog, nil)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("attaching tracepoint %s/%s: %w", p.group, p.name, err)
		}
		l.links = append(l.links, lnk)
		log.Printf("attached tracepoint %s/%s", p.group, p.name)
	}

	reader, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}
	l.reader = reader

	return reader, nil
}

// AddPID adds a PID to the target_pids map so the eBPF programs track it
func (l *Loader) AddPID(pid uint32) error {
	val := uint8(1)
	if err := l.objs.TargetPids.Put(pid, val); err != nil {
		return fmt.Errorf("adding PID %d to target map: %w", pid, err)
	}
	log.Printf("tracking PID %d", pid)
	return nil
}

// RemovePID removes a PID from the target_pids map
func (l *Loader) RemovePID(pid uint32) error {
	if err := l.objs.TargetPids.Delete(pid); err != nil {
		return fmt.Errorf("removing PID %d from target map: %w", pid, err)
	}
	return nil
}

// Close detaches all programs and releases resources
// TODO: ensure all programs detached correctly
func (l *Loader) Close() {
	if l.reader != nil {
		l.reader.Close()
	}
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.objs.Close()
}
