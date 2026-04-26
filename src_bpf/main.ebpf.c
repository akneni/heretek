#include "../if/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#include "../if/syscalls.h"
#include "utils.c"
#include "events.c"

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_ACCMODE 3

#define LSM_DENY 0
#define LSM_ALLOW 1

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    event *evt;
    const char *filename;
    int flags;
    int accmode;

    evt = reserve_event_slot();
    if (!evt) {
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

SEC("lsm/task_kill")
int handle_task_kill(
    struct task_struct *p, struct kernel_siginfo *info,
	int sig, const struct cred *cred
) {
    parameters *params = get_params();
    // pid_t pid = p.;




    if (
        params &&
        bit_test(params->flags, PARAM_FLG_IMMORTAL)
    ) {
        return LSM_DENY;
    }

    return LSM_ALLOW;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    event *evt = reserve_event_slot();

    if (!evt) {
        return 0;
    }

    evt->event = GENE_START;
    evt->pid = ctx->child_pid;
    evt->ktime = bpf_ktime_get_tai_ns();
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
    evt->ktime = bpf_ktime_get_tai_ns();
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
    evt->ktime = bpf_ktime_get_tai_ns();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
