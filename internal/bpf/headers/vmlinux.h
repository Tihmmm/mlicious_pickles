/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal vmlinux.h for MLiciousPickles eBPF programs.
 *
 * Contains only the kernel types required by our tracepoint programs.
 * On the target system (Ubuntu 24.04, kernel 6.8+), regenerate the full
 * vmlinux.h with:
 *
 *     bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed char        __s8;
typedef signed short       __s16;
typedef signed int         __s32;
typedef signed long long   __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

/* Boolean type used by BPF helpers. */
typedef int bool;
#define true  1
#define false 0

/* BPF map types */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC        = 0,
	BPF_MAP_TYPE_HASH          = 1,
	BPF_MAP_TYPE_ARRAY         = 2,
	BPF_MAP_TYPE_PROG_ARRAY    = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_RINGBUF       = 27,
};

/* BPF map update flags */
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

/* sk_buff for bpf_helper_defs.h (opaque - we never use it directly). */
struct __sk_buff {
	__u32 len;
};

/*
 * Tracepoint context for syscalls/sys_enter_*.
 * The 'args' array carries the syscall arguments (up to 6).
 */
struct trace_event_raw_sys_enter {
	__u64 unused;    /* common trace fields (type, flags, etc.) */
	__s32 __padding; /* alignment */
	__s32 id;        /* syscall number */
	__u64 args[6];   /* syscall arguments */
};

/*
 * Tracepoint context for syscalls/sys_exit_*.
 * 'ret' carries the syscall return value.
 */
struct trace_event_raw_sys_exit {
	__u64 unused;
	__s32 __padding;
	__s32 id;
	__s64 ret;
};

/*
 * Socket address structures - used to parse connect() arguments.
 */
typedef unsigned short sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char        sa_data[14];
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	sa_family_t    sin_family;
	__be16         sin_port;
	struct in_addr sin_addr;
	char           sin_zero[8];
};

struct in6_addr {
	union {
		__u8  u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct sockaddr_in6 {
	sa_family_t     sin6_family;
	__be16          sin6_port;
	__be32          sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32           sin6_scope_id;
};

#endif /* __VMLINUX_H__ */