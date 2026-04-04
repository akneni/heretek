#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../if/syscalls.h"

#define EVENT_BUFFER_SLOTS 64
#define EVENT_METADATA_SLOT EVENT_BUFFER_SLOTS

typedef struct event {
    __u32 event;
    __s32 pid;
    char fpath1[256];
    char fpath2[256];
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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, EVENT_BUFFER_SLOTS + 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(event_slot));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 md_key = EVENT_METADATA_SLOT;
    event_array_md *md = (event_array_md *)bpf_map_lookup_elem(&events, &md_key);
    __u32 event_key;
    event *evt;
    const char *filename = (const char *)ctx->args[1];

    if (!md) {
        return 0;
    }

    event_key = (__u32)(md->head % EVENT_BUFFER_SLOTS);
    evt = (event *)bpf_map_lookup_elem(&events, &event_key);
    if (!evt) {
        return 0;
    }

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event = SYSCALL_OPENAT;
    evt->pid = (__s32)(bpf_get_current_pid_tgid() >> 32);
    if (filename != 0) {
        bpf_probe_read_user_str(evt->fpath1, sizeof(evt->fpath1), filename);
    }

    md->head += 1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
