//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH   256
#define MAX_COMM   16
#define MAX_CHUNK  512

char LICENSE[] SEC("license") = "GPL";

volatile const u32 target_pid = 0;

struct pid_fd {
    u32 pid;
    s32 fd;
};

struct file_info {
    bool is_pkl;
    u64 offset;
};

struct open_state {
    char path[MAX_PATH];
};

struct read_args {
    s32 fd;
    u64 count;
};

struct event {
    u32 pid;
    s32 fd;
    u64 offset;
    u32 data_len;
    u32 flags;     // bit0: CLOSE event
    char comm[MAX_COMM];
    char path[MAX_PATH];
    u8  data[MAX_CHUNK];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pid_fd);
    __type(value, struct file_info);
} tracked_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, struct open_state);
} open_tmp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, struct read_args);
} read_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, __u64);
} read_buf_ptrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pid_fd);
    __type(value, char[MAX_PATH]);
} path_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, s32);
} close_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


static __inline bool is_target_pid(u32 pid) {
    return (target_pid != 0 && pid == target_pid);
}

static __inline bool endswith_pkl(const char *s, struct pid_fd *key) {
    char buf[64];
    long n = bpf_probe_read_user_str(buf, sizeof(buf), s);
    if (n <= 4) return false;
    
    int len = n - 1;
    if (len >= sizeof(buf) || len < 4) return false;

    char fullpath[MAX_PATH];
    if (bpf_probe_read_user_str(fullpath, MAX_PATH, s) > 0) {
        bpf_map_update_elem(&path_map, key, fullpath, BPF_ANY);
    }

    if (len >= 4 && len < sizeof(buf)) {
        if (buf[len - 4] == '.' &&
            (buf[len - 3] == 'p' || buf[len - 3] == 'P') &&
            (buf[len - 2] == 'k' || buf[len - 2] == 'K') &&
            (buf[len - 1] == 'l' || buf[len - 1] == 'L')) {
            return true;
        }
    }

    return false;
}


SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (!is_target_pid) {
        return 0;
    }

    const char *filename = (const char *)ctx->args[1];
    if (!filename) return 0;

    struct open_state st = {};
    if (bpf_probe_read_user_str(&st.path, sizeof(st.path), filename) <= 0)
        return 0;
    bpf_map_update_elem(&open_tmp, &pid, &st, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (!is_target_pid) {
        return 0;
    }

    s64 fd = ctx->ret;
    if (fd < 0) {
        bpf_map_delete_elem(&open_tmp, &pid);
        return 0;
    }

    struct open_state *st = bpf_map_lookup_elem(&open_tmp, &pid);
    if (!st) return 0;

    struct pid_fd key = {.pid = pid, .fd = (s32)fd};
    bool is_pkl = endswith_pkl(st->path, &key);

    struct file_info fi = {
        .is_pkl = is_pkl,
        .offset = 0,
    };

    bpf_map_update_elem(&tracked_fds, &key, &fi, BPF_ANY);
    bpf_map_delete_elem(&open_tmp, &pid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (!is_target_pid) {
        return 0;
    }

    struct read_args ra = {
        .fd = (s32)ctx->args[0],
        .count = (u64)ctx->args[2],
    };

    bpf_map_update_elem(&read_ctx, &pid, &ra, BPF_ANY);

    __u64 buf = (__u64)ctx->args[1];
    bpf_map_update_elem(&read_buf_ptrs, &pid, &buf, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (!is_target_pid) {
        return 0;
    }

    s64 ret = ctx->ret;

    struct read_args *ra = bpf_map_lookup_elem(&read_ctx, &pid);
    __u64 *buf_ptr = bpf_map_lookup_elem(&read_buf_ptrs, &pid);
    if (!ra || !buf_ptr || ret <= 0) goto cleanup_read;

    struct pid_fd key = {.pid = pid, .fd = ra->fd};
    struct file_info *fi = bpf_map_lookup_elem(&tracked_fds, &key);
    if (fi) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

        if (e) {
            __builtin_memset(e, 0, sizeof(*e));
            e->pid = pid;
            e->fd = ra->fd;
            e->offset = fi->offset;
            bpf_get_current_comm(e->comm, sizeof(e->comm));

            char *pathbuf = bpf_map_lookup_elem(&path_map, &key);

            if (pathbuf)
                __builtin_memcpy(e->path, pathbuf, MAX_PATH);

            u32 to_copy = (u32)(ret < MAX_CHUNK ? ret : MAX_CHUNK);

            if (to_copy > 0) {
                long r = bpf_probe_read_user(e->data, to_copy,
                                            (const void *)*buf_ptr);
                if (r == 0)
                    e->data_len = to_copy;
            }

            bpf_ringbuf_submit(e, 0);
            fi->offset += (u64)ret;
        }
    }

cleanup_read:
    bpf_map_delete_elem(&read_ctx, &pid);
    bpf_map_delete_elem(&read_buf_ptrs, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tp_enter_close(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (!is_target_pid) {
            return 0;
    }

    s32 fd = (s32)ctx->args[0];
    bpf_map_update_elem(&close_fd, &pid, &fd, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tp_exit_close2(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (!is_target_pid) {
        return 0;
    }

    if (ctx->ret == 0) {
        s32 *fdp = bpf_map_lookup_elem(&close_fd, &pid);

        if (fdp) {
            struct pid_fd key = {.pid = pid, .fd = *fdp};
            struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

            if (e) {
                __builtin_memset(e, 0, sizeof(*e));
                e->pid = pid;
                e->fd = *fdp;
                e->offset = 0;
                e->flags = 1;
                bpf_get_current_comm(e->comm, sizeof(e->comm));

                char *pathbuf = bpf_map_lookup_elem(&path_map, &key);

                if (pathbuf)
                    __builtin_memcpy(e->path, pathbuf, MAX_PATH);

                bpf_ringbuf_submit(e, 0);
            }

            bpf_map_delete_elem(&tracked_fds, &key);
            bpf_map_delete_elem(&path_map, &key);
        }
    }

    bpf_map_delete_elem(&close_fd, &pid);

    return 0;
}
