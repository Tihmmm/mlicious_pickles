# MLiciousPickles - High-Level Design

## Overview

MLiciousPickles is an eBPF-based dynamic pickle scanner that analyzes the
runtime behavior of Python pickle files during deserialization. Instead of
relying on static analysis of pickle opcodes, it instruments the kernel to
observe what the deserializing process actually *does* - which syscalls it
makes, which files it touches, which processes it spawns, and which network
connections it initiates.

## Architecture

```
┌─────────────────────── user space ───────────────────────────────────┐
│                                                                      │
│  ┌─────────────── MLiciousPickles (Go) ──────────────┐               │
│  │                                                   │               │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │  ┌──────────┐ │
│  │  │  eBPF    │  │ Analyzer │  │   Scanner        │ │  │  python3 │ │
│  │  │  Loader  │  │ (rules)  │  │   (orchestrator) │─┼─▶│  pickle  │ │
│  │  └────┬─────┘  └────▲─────┘  └────────┬─────────┘ │  │  .loads()│ │
│  │       │              │                 │          │  └──────────┘ │
│  │       │ load/attach  │ events          │ verdict  │      PID=N    │
│  └───────┼──────────────┼────────────────┼───────────┘               │
│          │              │                 ▼                          │
│          │        ring buffer         stdout / JSON                  │
├──────────┼──────────────┼────────────────────────────────────────────┤
│          ▼              │              kernel space                  │
│  ┌───────────────── eBPF VM ─────────────────────────────────┐       │
│  │                                                           │       │
│  │  tracepoint/syscalls/sys_enter_execve    ──┐              │       │
│  │  tracepoint/syscalls/sys_enter_openat    ──┤              │       │
│  │  tracepoint/syscalls/sys_enter_connect   ──┤  filter by   │       │
│  │  tracepoint/syscalls/sys_enter_socket    ──┤  PID → ring  │       │
│  │  tracepoint/syscalls/sys_enter_write     ──┤  buffer      │       │
│  │  tracepoint/syscalls/sys_enter_unlinkat  ──┤              │       │
│  │  tracepoint/syscalls/sys_enter_clone     ──┘              │       │
│  │                                                           │       │
│  │  tracepoint/sched/sched_process_fork   → add child PID    │       │
│  │  tracepoint/sched/sched_process_exit   → remove PID       │       │
│  │                                                           │       │
│  │  Maps:                                                    │       │
│  │    target_pids  (hash)   - PIDs under observation         │       │
│  │    events       (ringbuf) - event stream to userspace     │       │
│  └───────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────┘
```

## Workflow

1. **Load & Attach** - The Go userspace loads compiled eBPF programs into the
   kernel via `cilium/ebpf`, attaches them to tracepoints, and populates the
   `target_pids` map.

2. **Spawn Target** - The scanner spawns `python3` to deserialize the target
   pickle file. The child PID is added to the `target_pids` BPF map.

3. **Intercept** - eBPF tracepoint programs fire on every matching syscall
   system-wide, but only emit events for PIDs present in `target_pids`.
   When a tracked process forks, the child PID is automatically added.

4. **Collect** - Events flow from eBPF ring buffer to Go userspace via
   memory-mapped polling (epoll-driven by `cilium/ebpf`).

5. **Analyze** - The behavioral analyzer inspects the collected event stream
   and produces a verdict: **safe**, **suspicious**, or **malicious**.

## Event Types

| Event             | Trigger Syscall      | Key Data Captured                        |
|-------------------|----------------------|------------------------------------------|
| `EventExecve`     | `execve`             | filename, argv (first 4 args)            |
| `EventOpenat`     | `openat`             | filename, flags                          |
| `EventConnect`    | `connect`            | address family, IP, port                 |
| `EventSocket`     | `socket`             | domain, type, protocol                   |
| `EventWrite`      | `write`              | fd, byte count                           |
| `EventUnlinkat`   | `unlinkat`           | filename                                 |
| `EventClone`      | `clone` / `clone3`   | child PID, clone flags                   |

## Detection Rules

The analyzer applies behavioral rules to the event stream:

| Rule                | Severity   | Condition                                                       |
|---------------------|------------|-----------------------------------------------------------------|
| Process execution   | CRITICAL   | Any `execve` call from the deserialization process              |
| Reverse shell       | CRITICAL   | `socket` + `connect` to external IP + `execve` of a shell      |
| Network connection  | HIGH       | `connect` to any external address                               |
| Sensitive file read | HIGH       | `openat` of `/etc/passwd`, `/etc/shadow`, SSH keys, etc.        |
| File write          | MEDIUM     | `write` to files outside of expected paths (temp dirs, caches)  |
| File deletion       | MEDIUM     | `unlinkat` of any file                                          |
| Process creation    | MEDIUM     | `clone` with new process flags (not threads)                    |
| Socket creation     | LOW        | `socket` call (without subsequent connect)                      |

The final verdict is the maximum severity observed:
- **Safe** - no rules triggered
- **Suspicious** - only LOW/MEDIUM rules triggered
- **Malicious** - any HIGH or CRITICAL rule triggered

## Technology Choices

| Component         | Choice              | Rationale                                                    |
|-------------------|---------------------|--------------------------------------------------------------|
| Userspace lang    | Go                  | Strong eBPF ecosystem (`cilium/ebpf`), good concurrency      |
| Kernel lang       | C                   | Required by the eBPF verifier / LLVM BPF backend             |
| eBPF library      | `cilium/ebpf`       | Pure Go, no CGo, `bpf2go` code generation                    |
| BPF CO-RE         | `vmlinux.h` (BTF)   | Portable across kernel versions without recompilation         |
| Target OS         | Ubuntu 24.04.4 LTS  | Kernel 6.8, full BTF and ring buffer support                  |

## Project Structure

```
prototype/
├── cmd/
│   └── mliciouspickles/
│       └── main.go                # CLI entry point
├── internal/
│   ├── bpf/
│   │   ├── bpf.go                 # go:generate + loader
│   │   ├── headers/
│   │   │   └── vmlinux.h          # BTF-generated kernel types
│   │   └── c/
│   │       └── scanner.c          # eBPF C programs (all tracepoints)
│   ├── analyzer/
│   │   └── analyzer.go            # Behavioral analysis engine
│   ├── events/
│   │   └── types.go               # Go event type definitions
│   └── scanner/
│       └── scanner.go             # Orchestrator
├── docs/
│   ├── HLD.md                     # This document
│   ├── HLD.excalidraw
│   └── HLD.png
├── go.mod
├── Makefile
└── README.md
```

## Build Pipeline

```
make vmlinux    →  bpftool btf dump → vmlinux.h
make generate   →  bpf2go (clang → .o + Go bindings)
make build      →  go build → ./bin/mliciouspickles
```

## Future / Optional Extensions

- **YARA integration** - scan collected trace data or spawned binaries with YARA rules
- **Container isolation** - run the target pickle inside a minimal container (namespaced, seccomp-filtered) for defense-in-depth
- **XDP network filtering** - drop outbound packets from the target process at the NIC level
- **JSON/structured logging** - machine-readable output for CI/CD pipeline integration
- **Batch scanning** - scan multiple pickle files in sequence or parallel
