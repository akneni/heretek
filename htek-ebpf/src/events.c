#ifndef EVENTS_C
#define EVENTS_C

#define EVENT_BUF_SLOTS_LOG2 8
#define EVENT_BUFFER_SLOTS (1 << EVENT_BUF_SLOTS_LOG2)
#define EVENT_METADATA_SLOT EVENT_BUFFER_SLOTS
#define EVENT_PARAM_SLOT (EVENT_BUFFER_SLOTS - 1)

typedef struct event {
    __u32 event;
    __s32 pid;
    __u64 ktime;
    char fpath1[256];
    char fpath2[256];
    __u8 spare[8];

} event;

typedef struct event_array_md {
    __u64 head;
} event_array_md;

#define PARAM_FLG_IMMORTAL 0 // Blocks all attempts to kill the heretek daemon
#define PARAM_FLG_BOFRB    1 // Block on Full Ring Buffer
typedef struct parameters {
    __u64 flags;
    __s32 daemon_pid;
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

#endif
