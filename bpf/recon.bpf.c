// recon: uprobe every JNI slot + uretprobe a tracked subset.
// - args are snapshotted at event time (volatile stack)
// - return values (x0) captured at uretprobe, paired by (tid, depth)
// - depth = count of active tracked frames on the thread, so nested calls pair
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define NARGS 5
#define NCAP  16

struct evt_t {
    __u32 pid;
    __u32 tid;
    __u32 kind;   // 0 entry, 1 return
    __u32 pad;
    __u64 ip;
    __u64 rc;
    __u64 ts;     // bpf_ktime_get_ns()
    __s32 depth;  // matching depth for tracked slots, -1 otherwise
    __u32 pad2;
    __u64 caller; // entry: caller return address (x30/LR)
    __u64 a[NARGS];
    __u32 ncap;
    __u32 argkind;
    __u32 res1;
    __u32 res2;
    __u64 cap[NCAP];
    __u64 cap2[NCAP];
    __u64 vgr;
    __s64 vgoff;
    __u64 vstk;
    __s32 stackid;
    __u32 pad3;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} cfg SEC(".maps"); // [0]=libart base, [1]=want_stack

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 32 * sizeof(__u64));
} stackmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);
    __type(value, __u8);
} argkind SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);
    __type(value, __u8);
} argidx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u8);
} hasret SEC(".maps"); // file-offset -> has a return probe

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} depth SEC(".maps"); // tid -> active tracked frame depth

static __always_inline void capture(struct evt_t *e, __u64 p, int k, int ix)
{
    e->argkind = k;
    e->ncap = NCAP;
    if (k == 1) { // jvalue*
#pragma unroll
        for (int i = 0; i < NCAP; i++) {
            __u64 v = 0;
            bpf_probe_read_user(&v, 8, (void *)(p + (__u64)i * 8));
            e->cap[i] = v;
        }
    } else if (k == 2) { // va_list*
        __u64 st[4] = {0, 0, 0, 0};
        bpf_probe_read_user(st, sizeof(st), (void *)p);
        e->vstk = st[0];
        e->vgr = st[1];
        e->vgoff = (__s64)(int)st[3];
        __u64 gbase = st[1] - 128;
#pragma unroll
        for (int i = 0; i < NCAP; i++) {
            __u64 v = 0;
            bpf_probe_read_user(&v, 8, (void *)(gbase + (__u64)i * 8));
            e->cap[i] = v;
        }
#pragma unroll
        for (int i = 0; i < NCAP; i++) {
            __u64 v = 0;
            bpf_probe_read_user(&v, 8, (void *)(st[0] + (__u64)i * 8));
            e->cap2[i] = v;
        }
    } else if (k == 3) { // variadic C: args in entry regs a[ix..]
        e->ncap = NARGS - (__u32)ix;
        e->cap[0] = e->a[ix];
        e->cap[1] = (ix + 1 < NARGS) ? e->a[ix + 1] : 0;
    }
}

SEC("uprobe")
int BPF_KPROBE(up_all)
{
    struct evt_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pt;
    e->pid = pt >> 32;
    e->tid = tid;
    e->kind = 0;
    e->pad = 0;
    e->ip = PT_REGS_IP(ctx);
    e->rc = 0;
    e->ts = bpf_ktime_get_ns();
    e->depth = -1;
    e->pad2 = 0;
    e->caller = PT_REGS_RET(ctx);
    e->a[0] = PT_REGS_PARM1(ctx);
    e->a[1] = PT_REGS_PARM2(ctx);
    e->a[2] = PT_REGS_PARM3(ctx);
    e->a[3] = PT_REGS_PARM4(ctx);
    e->a[4] = PT_REGS_PARM5(ctx);
    e->ncap = 0;
    e->argkind = 0;
    e->vgr = 0;
    e->vgoff = 0;
    e->vstk = 0;
    e->stackid = -1;
    e->pad3 = 0;

    __u32 zero = 0;
    __u64 *base = bpf_map_lookup_elem(&cfg, &zero);
    if (base) {
        __u64 off = e->ip - *base;
        __u8 *hr = bpf_map_lookup_elem(&hasret, &off);
        if (hr) { // tracked: maintain depth
            __u32 d = 0;
            __u32 *pd = bpf_map_lookup_elem(&depth, &tid);
            if (pd)
                d = *pd;
            __u32 nd = d + 1;
            bpf_map_update_elem(&depth, &tid, &nd, BPF_ANY);
            e->depth = (__s32)d;
        }
        __u8 *k = bpf_map_lookup_elem(&argkind, &off);
        __u8 *ix = bpf_map_lookup_elem(&argidx, &off);
        if (k && ix && *k != 0 && *ix < NARGS)
            capture(e, e->a[*ix], *k, *ix);
        __u32 one = 1;
        __u64 *ws = bpf_map_lookup_elem(&cfg, &one);
        if (ws && *ws)
            e->stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uretprobe")
int BPF_KPROBE(up_ret)
{
    struct evt_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pt;
    e->pid = pt >> 32;
    e->tid = tid;
    e->kind = 1;
    e->pad = 0;
    e->ip = PT_REGS_IP(ctx);
    e->rc = PT_REGS_PARM1(ctx); // x0 == return value
    e->ts = bpf_ktime_get_ns();
    e->depth = -1;
    e->pad2 = 0;
    e->caller = 0;
    e->a[0] = 0;
    e->a[1] = 0;
    e->a[2] = 0;
    e->a[3] = 0;
    e->a[4] = 0;
    e->ncap = 0;
    e->argkind = 0;
    e->vgr = 0;
    e->vgoff = 0;
    e->vstk = 0;
    e->stackid = -1;
    e->pad3 = 0;

    // every return event comes from a tracked slot (only those have uretprobes),
    // and uretprobe IP is the return address, so we cannot map ip->slot here.
    // Just pop one tracked frame off this thread's depth.
    __u32 d = 0;
    __u32 *pd = bpf_map_lookup_elem(&depth, &tid);
    if (pd)
        d = *pd;
    __u32 nd = (d > 0) ? d - 1 : 0;
    bpf_map_update_elem(&depth, &tid, &nd, BPF_ANY);
    e->depth = (__s32)nd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
