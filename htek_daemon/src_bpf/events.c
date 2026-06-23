#include "../if_bpf/vmlinux.h"
#include "../if_bpf/build_params.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#ifndef EVENTS_C
#define EVENTS_C

#define EVENT_BUFFER_SLOTS (1 << RING_BUF_SIZE_LOG2)
#define EVENT_METADATA_SLOT (EVENT_BUFFER_SLOTS + 0)
#define EVENT_PARAM_SLOT (EVENT_BUFFER_SLOTS + 1)

typedef struct canary_t {
    __u32 cpu_id;
    __u32 magic_num;
} canary_t;

typedef struct event {
    __u32 event;
    __s32 pid;
    __u64 ktime;
    char fpath1[256];
    char fpath2[256];
    __u8 spare[8];

} event;

typedef struct event_array_md {
    canary_t canary;
    __u32 tail;
    __u32 head;
} event_array_md;

#define PARAM_FLG_IMMORTAL 0 // Blocks all attempts to kill the heretek daemon
#define PARAM_FLG_BOFRB    1 // Block on Full Ring Buffer
typedef struct parameters {
    canary_t canary;
    __u64 flags;
    __s32 daemon_pid;
} parameters;

typedef union event_slot {
    event evt;
    event_array_md md;
    parameters params;
} event_slot;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, EVENT_BUFFER_SLOTS + NUM_CORES + 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(event_slot));
	__uint(map_flags, BPF_F_MMAPABLE);
} events SEC(".maps");

static __always_inline parameters *get_params() {
    __u32 md_key = EVENT_PARAM_SLOT;
    return (parameters *)bpf_map_lookup_elem(&events, &md_key);
}

static __always_inline void check_canary(canary_t *can) {
    if (!ASSERTS) return;

    bool is_unset = can->cpu_id == 0 && can->magic_num == 0;

    if (unlikely(is_unset)) {
        can->cpu_id = bpf_get_smp_processor_id();
        can->magic_num = CANARY;
    } else {
        if (can->cpu_id != bpf_get_smp_processor_id() || can->magic_num != CANARY) {
            bpf_printk("Canary Died on core %u", bpf_get_smp_processor_id());
        }
    }
}

/// This function does NOT zero out the event struct
static __always_inline event *reserve_event_slot() {
    __u32 cpuid = bpf_get_smp_processor_id();
    __u32 map_len = (EVENT_BUFFER_SLOTS / NUM_CORES);
    __u32 map_offset = map_len * cpuid;
    __u32 md_key = EVENT_BUFFER_SLOTS + cpuid;
    event_array_md *md = (event_array_md *)bpf_map_lookup_elem(&events, &md_key);
    __u32 next_head;
    __u32 real_idx;
    event *evt;

    if (unlikely(md == NULL)) {
        return NULL;
    }

    check_canary(&md->canary);

    next_head = (md->head + 1) % map_len;
    if (unlikely(next_head == md->tail)) {
        return NULL;
    }

    real_idx = md->head + map_offset;
    evt = (event *)bpf_map_lookup_elem(&events, &real_idx);
    if (unlikely(evt == NULL)) {
        return NULL;
    }
    if (ASSERTS) {
        evt->pid = 0;
        evt->event = 0;
        evt->ktime = 0;
    }
    return evt;
}

static __always_inline void commit_event(const event* evt) {
    __u32 cpuid = bpf_get_smp_processor_id();
    __u32 map_len = (EVENT_BUFFER_SLOTS / NUM_CORES);
    __u32 md_key = EVENT_BUFFER_SLOTS + cpuid;
    event_array_md *md = (event_array_md *)bpf_map_lookup_elem(&events, &md_key);
    __u32 next_head;
    barrier();

    if (unlikely(md == NULL)) {
        return;
    }

    check_canary(&md->canary);

    next_head = (md->head + 1) % map_len;
    if (ASSERTS) {
        if (next_head == md->tail)
            bpf_printk("Tried to commit a buffer slot while the ring buffer was full\n");

        if (evt->pid == 0 || evt->event == 0 || evt->ktime == 0)
            bpf_printk("Failed to set required fields");

    }

    md->head = next_head;
}

#endif
