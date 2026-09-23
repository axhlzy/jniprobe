// envprobe: capture a live JNIEnv* by uprobing exported libart functions,
// then dump the process-global JNINativeInterface function table.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define NSLOTS 240

struct dump_t {
    __u32 pid;
    __u32 site;   // 1 = LoadNativeLibrary, 2 = CreateNativeThread
    __u32 reg;    // 0 => arg0, 1 => arg1
    __u32 pad;
    __u64 env;    // candidate JNIEnv*
    __u64 table;  // *(JNIEnv*) == JNINativeInterface*
    __u64 slots[NSLOTS];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} seen SEC(".maps");

static __always_inline void emit(struct pt_regs *ctx, __u32 site, __u32 reg, __u64 cand)
{
    if (cand < 0x10000)
        return;

    __u64 table = 0;
    if (bpf_probe_read_user(&table, sizeof(table), (void *)cand) != 0)
        return;
    // JNINativeInterface* lives in libart's read-only segment, a normal user ptr.
    if (table < 0x10000 || table > 0x0000800000000000ULL)
        return;
    // table slot #6 is GetVersion (a code pointer), sanity check it too.
    __u64 v = 0;
    if (bpf_probe_read_user(&v, sizeof(v), (void *)(table + 6 * 8)) != 0)
        return;
    if (v < 0x10000)
        return;

    struct dump_t *d = bpf_ringbuf_reserve(&events, sizeof(*d), 0);
    if (!d)
        return;
    d->pid   = bpf_get_current_pid_tgid() >> 32;
    d->site  = site;
    d->reg   = reg;
    d->pad   = 0;
    d->env   = cand;
    d->table = table;
#pragma unroll
    for (int i = 0; i < NSLOTS; i++) {
        __u64 s = 0;
        bpf_probe_read_user(&s, sizeof(s), (void *)(table + (__u64)i * 8));
        d->slots[i] = s;
    }
    bpf_ringbuf_submit(d, 0);
}

SEC("uprobe")
int BPF_KPROBE(up_lnl)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&seen, &pid))
        return 0;
    // art::JavaVMExt::LoadNativeLibrary is a non-static member -> x0=this, x1=env
    emit(ctx, 1, 1, PT_REGS_PARM2(ctx));
    emit(ctx, 1, 0, PT_REGS_PARM1(ctx));
    __u8 one = 1;
    bpf_map_update_elem(&seen, &pid, &one, BPF_ANY);
    return 0;
}

SEC("uprobe")
int BPF_KPROBE(up_cnt)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&seen, &pid))
        return 0;
    // art::Thread::CreateNativeThread is static -> x0=env
    emit(ctx, 2, 0, PT_REGS_PARM1(ctx));
    emit(ctx, 2, 1, PT_REGS_PARM2(ctx));
    __u8 one = 1;
    bpf_map_update_elem(&seen, &pid, &one, BPF_ANY);
    return 0;
}
