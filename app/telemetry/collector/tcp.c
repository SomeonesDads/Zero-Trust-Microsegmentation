/* Original BCC probe implementation for the isolated IPv4/TCP lab.
 * Read-only observation: no packet verdicts or modifications. */
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

struct event_t {
    u64 timestamp_ns;
    u64 cgroup_id;
    u32 netns_id;
    u32 pid;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    s32 result;
    u32 kind;
    char comm[16];
};
BPF_HASH(allowed_netns, u32, u8, 128);
BPF_HASH(connecting, u64, struct sock *, 16384);
BPF_LRU_HASH(accepted, u64, u8, 32768);
BPF_PERF_OUTPUT(events);
/* attempted output, submit failures, entry-map failures */
BPF_ARRAY(counters, u64, 3);

static inline void count(u32 key) {
    u64 *value = counters.lookup(&key);
    if (value) __sync_fetch_and_add(value, 1);
}

static inline u32 namespace_id(struct sock *sk) {
    struct net *net = sk->__sk_common.skc_net.net;
    return net->ns.inum;
}

static inline int emit(struct pt_regs *ctx, struct sock *sk, u32 kind, int result) {
    if (!sk || sk->__sk_common.skc_family != AF_INET) return 0;
    u32 ns = namespace_id(sk);
    if (!allowed_netns.lookup(&ns)) return 0;
    struct event_t event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.netns_id = ns;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.src_ip = sk->__sk_common.skc_rcv_saddr;
    event.dst_ip = sk->__sk_common.skc_daddr;
    event.src_port = sk->__sk_common.skc_num;
    event.dst_port = ntohs(sk->__sk_common.skc_dport);
    event.kind = kind;
    event.result = result;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    count(0);
    if (events.perf_submit(ctx, &event, sizeof(event)) < 0) count(1);
    return 0;
}

int connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 ns = namespace_id(sk);
    if (!allowed_netns.lookup(&ns)) return 0;
    u64 key = bpf_get_current_pid_tgid();
    if (connecting.update(&key, &sk) < 0) count(2);
    return 0;
}

int connect_return(struct pt_regs *ctx) {
    u64 key = bpf_get_current_pid_tgid();
    struct sock **entry = connecting.lookup(&key);
    if (!entry) return 0;
    struct sock *sk = *entry;
    emit(ctx, sk, 1, PT_REGS_RC(ctx));
    connecting.delete(&key);
    return 0;
}

int accept_return(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if ((long)sk <= 0) return 0;
    u32 ns = namespace_id(sk);
    if (!allowed_netns.lookup(&ns)) return 0;
    u64 key = (u64)sk;
    u8 value = 1;
    accepted.update(&key, &value);
    return emit(ctx, sk, 2, 0);
}

int close_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 key = (u64)sk;
    u32 kind = accepted.lookup(&key) ? 4 : 3;
    accepted.delete(&key);
    return emit(ctx, sk, kind, 0);
}
