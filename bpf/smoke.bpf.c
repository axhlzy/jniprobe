// smoke test: validate clang -target bpf + kprobe/uprobe + ringbuf on the device
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct event_t {
    __u32 pid;
    __u32 pad;
    __u64 ip;
    __u64 parm1;
    __u64 parm2;
    __u64 parm3;
    char  tag[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline void fill(struct pt_regs *ctx, const char *tag)
{
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->pad   = 0;
    e->ip    = PT_REGS_IP(ctx);
    e->parm1 = PT_REGS_PARM1(ctx);
    e->parm2 = PT_REGS_PARM2(ctx);
    e->parm3 = PT_REGS_PARM3(ctx);
    __builtin_memset(e->tag, 0, sizeof(e->tag));
    __builtin_memcpy(e->tag, tag, 15);
    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/__arm64_sys_getpid")
int BPF_KPROBE(kp_getpid)
{
    fill(ctx, "kprobe");
    return 0;
}

SEC("uprobe")
int BPF_KPROBE(up_generic)
{
    fill(ctx, "uprobe");
    return 0;
}
