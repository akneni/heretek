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

typedef struct event {
    __u32 event;
    __s32 pid;
    __u64 ktime;
    char fpath1[256];
    char fpath2[256];
    __u8 spare[8];

} event;

typedef struct event_array_md {
    __u32 canary;
    __u32 length;
} event_array_md;

#define PARAM_FLG_IMMORTAL 0 // Blocks all attempts to kill the heretek daemon
#define PARAM_FLG_BOFRB    1 // Block on Full Ring Buffer
typedef struct parameters {
    __u32 canary;
    __s32 daemon_pid;
    __u64 flags;
} parameters;

typedef union event_slot {
    event evt;
    event_array_md md;
    parameters params;
} event_slot;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, EVENT_BUFFER_SLOTS + 2);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(event_slot));
} events SEC(".maps");

static __always_inline parameters *get_params() {
    __u32 md_key = EVENT_PARAM_SLOT;
    return (parameters *)bpf_map_lookup_elem(&events, &md_key);
}

static void check_canary() {
    if (!ASSERTS) return;

    __u32 evtmd_key = EVENT_METADATA_SLOT;
    event_array_md *evtmd = (event_array_md *)bpf_map_lookup_elem(&events, &evtmd_key);
    __u32 param_key = EVENT_PARAM_SLOT;
    parameters *param = (parameters *)bpf_map_lookup_elem(&events, &param_key);

    if (evtmd != NULL) {
        if (evtmd->canary == 0) evtmd->canary = EVTMD_CANARY;
        if (evtmd->canary != EVTMD_CANARY) {
            bpf_printk("Event metadata canary died\n");
        }
    }

    if (param != NULL) {
        if (param->canary == 0) param->canary = EVTMD_CANARY;
        if (param->canary != PARAM_CANARY) {
            bpf_printk("Parameter canary died\n");
        }
    }
}

/// This function does NOT zero out the event struct
static __always_inline event *reserve_event_slot() {
    check_canary();

    __u32 md_key = EVENT_METADATA_SLOT;
    event_array_md *md = (event_array_md *)bpf_map_lookup_elem(&events, &md_key);
    __u32 event_key;
    event *evt;

    if (unlikely(md == NULL)) {
        return NULL;
    }
    if (unlikely(md->length >=EVENT_BUFFER_SLOTS)) {
        return NULL;
    }

    return (event *)bpf_map_lookup_elem(&events, &md->length);
}

static __always_inline void commit_event() {
    check_canary();

    __u32 md_key = EVENT_METADATA_SLOT;
    event_array_md *md = (event_array_md *)bpf_map_lookup_elem(&events, &md_key);

    if (unlikely(md == NULL)) {
        return;
    }

    if (ASSERTS && md->length >= EVENT_BUFFER_SLOTS) {
        bpf_printk("Tried to commit a buffer slot while the per CPU array was full\n");
    }

    md->length++;
}

#endif
