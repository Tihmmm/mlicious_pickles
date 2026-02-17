// SPDX-License-Identifier: GPL-2.0
// eBPF programs for MLiciousPickles - dynamic pickle scanner.
//
// Attaches to syscall tracepoints to monitor process behavior during
// Python pickle deserialization. Events are filtered by PID and sent
// to userspace via a ring buffer.

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_ARG_LEN      128
#define MAX_ARGS         4

char LICENSE[] SEC("license") = "GPL";

// Event types (keep in sync with internal/events/types.go)

enum event_type {
    EVENT_EXECVE   = 1,
    EVENT_OPENAT   = 2,
    EVENT_CONNECT  = 3,
    EVENT_SOCKET   = 4,
    EVENT_WRITE    = 5,
    EVENT_UNLINKAT = 6,
    EVENT_CLONE    = 7,
};

// Event structures - ring buffer payload

struct event_header {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 _pad;
};

struct execve_event {
    struct event_header hdr;
    char  filename[MAX_FILENAME_LEN];
    char  argv[MAX_ARGS][MAX_ARG_LEN];
    __u32 argc;
    __u32 _pad;
};

struct openat_event {
    struct event_header hdr;
    char  filename[MAX_FILENAME_LEN];
    __s32 dirfd;
    __u32 flags;
};

struct connect_event {
    struct event_header hdr;
    __u16 addr_family;
    __u16 port;           // network byte order -> converted in userspace
    __u32 addr_v4;        // IPv4 address (if AF_INET)
    __u8  addr_v6[16];    // IPv6 address (if AF_INET6)
};

struct socket_event {
    struct event_header hdr;
    __u32 domain;
    __u32 type;
    __u32 protocol;
    __u32 _pad;
};

struct write_event {
    struct event_header hdr;
    __u32 fd;
    __u64 count;
    __u32 _pad;
};

struct unlinkat_event {
    struct event_header hdr;
    char  filename[MAX_FILENAME_LEN];
    __s32 dirfd;
    __u32 flags;
};

struct clone_event {
    struct event_header hdr;
    __u64 clone_flags;
    __u32 child_pid;
    __u32 _pad;
};

// Maps

// Hash map of PIDs we are tracking. Value is ignored (existence check only)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);
    __type(value, __u8);
} target_pids SEC(".maps");

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// Helpers

static __always_inline int pid_tracked(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&target_pids, &pid) != NULL;
}

static __always_inline void fill_header(struct event_header *hdr, __u32 type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    hdr->pid          = pid_tgid >> 32;
    hdr->tid          = (__u32)pid_tgid;
    hdr->timestamp_ns = bpf_ktime_get_ns();
    hdr->event_type   = type;
    hdr->_pad         = 0;
}

// Tracepoints

// execve
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_tracked())
        return 0;

    struct execve_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_EXECVE);

    // ctx->args[0] = filename
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // ctx->args[1] = argv array
    const char *const *argv = (const char *const *)ctx->args[1];
    e->argc = 0;
    __builtin_memset(e->argv, 0, sizeof(e->argv));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        bpf_probe_read_user_str(e->argv[i], MAX_ARG_LEN, argp);
        e->argc = i + 1;
    }

    e->_pad = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// openat
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_tracked())
        return 0;

    struct openat_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_OPENAT);

    e->dirfd = (__s32)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), pathname);
    e->flags = (__u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// connect
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_tracked())
        return 0;

    struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_CONNECT);

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    e->addr_family = family;
    e->port = 0;
    e->addr_v4 = 0;
    __builtin_memset(e->addr_v6, 0, sizeof(e->addr_v6));

    if (family == 2) { // AF_INET
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        bpf_probe_read_user(&e->port, sizeof(e->port), &sin->sin_port);
        bpf_probe_read_user(&e->addr_v4, sizeof(e->addr_v4), &sin->sin_addr);
    } else if (family == 10) { // AF_INET6
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        bpf_probe_read_user(&e->port, sizeof(e->port), &sin6->sin6_port);
        bpf_probe_read_user(e->addr_v6, sizeof(e->addr_v6), &sin6->sin6_addr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// socket
SEC("tracepoint/syscalls/sys_enter_socket")
int tracepoint_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_tracked())
        return 0;

    struct socket_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_SOCKET);

    e->domain   = (__u32)ctx->args[0];
    e->type     = (__u32)ctx->args[1];
    e->protocol = (__u32)ctx->args[2];
    e->_pad     = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// write
SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_tracked())
        return 0;

    struct write_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_WRITE);

    e->fd    = (__u32)ctx->args[0];
    e->count = (__u64)ctx->args[2];
    e->_pad  = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// unlinkat
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_tracked())
        return 0;

    struct unlinkat_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_UNLINKAT);

    e->dirfd = (__s32)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), pathname);
    e->flags = (__u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// clone
SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint_sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    if (!pid_tracked())
        return 0;

    struct clone_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_CLONE);

    e->clone_flags = (__u64)ctx->args[0];
    e->child_pid   = 0; // filled on sched_process_fork
    e->_pad        = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Process lifecycle tracking

// Fires after clone() returns.
// If the caller is tracked and a child was created (ret > 0), add the child PID to the tracking map
SEC("tracepoint/syscalls/sys_exit_clone")
int tracepoint_sys_exit_clone(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = ctx->ret;
    if (ret <= 0)
        return 0;

    __u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&target_pids, &parent_pid) == NULL)
        return 0;

    __u32 child_pid = (__u32)ret;
    __u8 val = 1;
    bpf_map_update_elem(&target_pids, &child_pid, &val, BPF_ANY);
    return 0;
}

// Fires when a process calls exit_group(). Remove from tracking map
SEC("tracepoint/syscalls/sys_enter_exit_group")
int tracepoint_sys_enter_exit_group(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&target_pids, &pid);
    return 0;
}
