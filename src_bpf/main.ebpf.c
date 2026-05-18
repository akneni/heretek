#include "../if_bpf/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#include "../if_bpf/syscalls.h"
#include "utils.c"
#include "events.c"

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_ACCMODE 3

#define SIGKILL 9

#define EPERM 1
#define LSM_ALLOW 0
#define LSM_DENY (-EPERM)

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    event *evt;
    const char *filename;
    int flags;
    int accmode;

    evt = reserve_event_slot();
    if (unlikely(!evt)) {
        return 0;
    }

    filename = (const char *)ctx->args[1];
    flags = (int)ctx->args[2];
    accmode = flags & O_ACCMODE;

    evt->event = SYSCALL_OPENAT;
    evt->pid = (__s32)(bpf_get_current_pid_tgid() >> 32);
    evt->ktime = bpf_ktime_get_tai_ns();
    if (likely(filename != 0)) {
        bpf_probe_read_user_str(evt->fpath1, sizeof(evt->fpath1), filename);
    }
    evt->spare[0] = (__u8)accmode;

    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    event *evt = reserve_event_slot();

    if (unlikely(!evt)) {
        return 0;
    }

    evt->event = GENE_START;
    evt->pid = ctx->child_pid;
    evt->ktime = bpf_ktime_get_tai_ns();
    ((__s32*)evt->spare)[0] = ctx->parent_pid;
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    event *evt = reserve_event_slot();
    const char *filename;

    if (unlikely(!evt)) {
        bpf_printk("Killing process(PID=%d) (ring-buf full)\n", ctx->pid);
        bpf_send_signal(SIGKILL);
        return 0;
    }

    evt->event = SYSCALL_EXECVE;
    evt->pid = ctx->pid;
    evt->ktime = bpf_ktime_get_tai_ns();
    filename = tracepoint_dyn_str(ctx, ctx->__data_loc_filename);
    bpf_probe_read_kernel_str(evt->fpath1, sizeof(evt->fpath1), filename);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    event *evt = reserve_event_slot();

    if (unlikely(!evt)) {
        return 0;
    }

    evt->event = GENE_EXIT;
    evt->pid = ctx->pid;
    evt->ktime = bpf_ktime_get_tai_ns();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
