#ifndef UTILS_C
#define UTILS_C

#include "../if/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#define likely(cond)   __builtin_expect(!!(cond),1)
#define unlikely(cond) __builtin_expect(!!(cond),0)

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

#endif
