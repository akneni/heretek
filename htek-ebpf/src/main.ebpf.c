#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

#include "../if/syscalls.h"

#define EVENT_BUFFER_SLOTS (256-1)
#define EVENT_METADATA_SLOT EVENT_BUFFER_SLOTS

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_ACCMODE 3
#define ACCESS_TYPE_R 0
#define ACCESS_TYPE_W 1
#define ACCESS_TYPE_E 2

typedef struct event {
    __u32 event;
    __s32 pid;
    char fpath1[256];
    char fpath2[256];
    __u8 spare[8];
} event;

typedef struct event_array_md {
    __u64 head;
} event_array_md;

typedef union event_slot {
    event evt;
    event_array_md md;
} event_slot;

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    unsigned long args[6];
};

struct trace_event_raw_sched_process_template {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    char comm[16];
    __s32 pid;
    __s32 prio;
};

struct trace_event_raw_sched_process_fork {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

struct trace_event_raw_sched_process_exec {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __u32 __data_loc_filename;
    __s32 pid;
    __s32 old_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, EVENT_BUFFER_SLOTS + 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(event_slot));
} events SEC(".maps");

/// This function does NOT zero out the event struct
static __always_inline event *reserve_event_slot() {
    __u32 md_key = EVENT_METADATA_SLOT;
    event_array_md *md = (event_array_md *)bpf_map_lookup_elem(&events, &md_key);
    __u32 event_key;
    event *evt;

    if (!md) {
        return 0;
    }

    event_key = (__u32)(md->head % EVENT_BUFFER_SLOTS);
    evt = (event *)bpf_map_lookup_elem(&events, &event_key);
    if (!evt) {
        return 0;
    }

    md->head += 1;
    return evt;
}

static __always_inline bool bit_test(__u8 bitmap, __u8 idx) {
    return (bitmap & (0x01 << idx)) != 0;
}

static __always_inline void bit_set(__u8 *bitmap, __u8 idx) {
    *bitmap = *bitmap | (0x01 << idx);
}

static __always_inline void bit_clear(__u8 *bitmap, __u8 idx) {
    *bitmap = *bitmap & (~(0x01 << idx));
}


static __always_inline const char *tracepoint_dyn_str(const void *ctx, __u32 data_loc) {
    return (const char *)ctx + (data_loc & 0xFFFF);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    event *evt = reserve_event_slot();
    const char *filename = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];
    int accmode = flags & O_ACCMODE;

    if (!evt) {
        return 0;
    }

    evt->event = SYSCALL_OPENAT;
    evt->pid = (__s32)(bpf_get_current_pid_tgid() >> 32);
    if (filename != 0) {
        bpf_probe_read_user_str(evt->fpath1, sizeof(evt->fpath1), filename);
    }
    if (accmode == O_RDONLY || accmode == O_RDWR) {
        bit_set(&evt->spare[0], ACCESS_TYPE_R);
    }
    if (accmode == O_WRONLY || accmode == O_RDWR) {
        bit_set(&evt->spare[0], ACCESS_TYPE_W);
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    event *evt = reserve_event_slot();

    if (!evt) {
        return 0;
    }

    evt->event = GENE_START;
    evt->pid = ctx->child_pid;
    *(__s32 *)evt->spare = ctx->parent_pid;
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    event *evt = reserve_event_slot();
    const char *filename;

    if (!evt) {
        return 0;
    }

    evt->event = SYSCALL_EXECVE;
    evt->pid = ctx->pid;
    filename = tracepoint_dyn_str(ctx, ctx->__data_loc_filename);
    bpf_probe_read_kernel_str(evt->fpath1, sizeof(evt->fpath1), filename);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    event *evt = reserve_event_slot();

    if (!evt) {
        return 0;
    }

    evt->event = GENE_EXIT;
    evt->pid = ctx->pid;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
