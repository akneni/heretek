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
    evt->ktime = bpf_ktime_get_boot_ns();
    if (likely(filename != 0)) {
        bpf_probe_read_user_str(evt->fpath1, sizeof(evt->fpath1), filename);
    }
    evt->spare[0] = (__u8)accmode;

    return 0;
}

SEC("tp_btf/sched_process_fork")
 int handle_process_fork(__u64 *ctx) {
     struct task_struct *parent = (struct task_struct *)ctx[0];
     struct task_struct *child = (struct task_struct *)ctx[1];
     event *evt;

     if (child->mm == NULL) {
         // New kthread has been spawned
         return 0;
     }

     if (child->pid != child->tgid) {
         // New non-main thread has been spawned
         return 0;
     }

     evt = reserve_event_slot();
     if (unlikely(!evt)) {
         return 0;
     }

     evt->event = GENE_START;
     evt->pid = child->tgid;
     evt->ktime = bpf_ktime_get_boot_ns();
     ((__s32 *)evt->spare)[0] = parent->tgid;
     return 0;
 }

SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    event *evt = reserve_event_slot();
    const char *filename;

    if (unlikely(!evt)) {
        return 0;
    }

    evt->event = SYSCALL_EXECVE;
    evt->pid = (__s32)(bpf_get_current_pid_tgid() >> 32);
    evt->ktime = bpf_ktime_get_boot_ns();
    filename = tracepoint_dyn_str(ctx, ctx->__data_loc_filename);
    bpf_probe_read_kernel_str(evt->fpath1, sizeof(evt->fpath1), filename);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    event *evt = reserve_event_slot();

    if (unlikely(!evt)) {
        return 0;
    }

    evt->event = GENE_EXIT;
    evt->pid = (__s32)(bpf_get_current_pid_tgid() >> 32);
    evt->ktime = bpf_ktime_get_boot_ns();
    return 0;
}

SEC("fexit/unix_stream_connect")
int on_unix_stream_connect(__u64 *ctx)
{
    struct sockaddr_un *addr = (struct sockaddr_un *)ctx[1];
    int addr_len = (int)ctx[2];
    int ret = (int)ctx[4];
    event *evt;

    if (ret != 0) {
        return 0;
    }

    evt = reserve_event_slot();
    if (unlikely(!evt)) {
        return 0;
    }

    evt->event = GENE_CONNECT_UDS;
    evt->pid = (__s32)(bpf_get_current_pid_tgid() >> 32);
    evt->ktime = bpf_ktime_get_boot_ns();
    evt->fpath1[0] = 0;
    evt->fpath2[0] = 0;
    ((__s32 *)evt->spare)[0] = ret;
    ((__s32 *)evt->spare)[1] = addr_len;

    if (addr && addr_len > sizeof(addr->sun_family)) {
        bpf_probe_read_kernel_str(evt->fpath1, sizeof(evt->fpath1), addr->sun_path);
    }

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
