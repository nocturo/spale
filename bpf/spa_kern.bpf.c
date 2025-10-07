// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "spa_common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct allowed_key);
    __type(value, struct allowed_entry);
} allowed_ipv4 SEC(".maps");

// IPv6 allowlist keyed by (src6, dport)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct allowed6_key);
    __type(value, struct allowed_entry);
} allowed_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct spa_config);
} config_map SEC(".maps");

struct rl_entry { __u64 last_ts; __u32 tokens; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rl_entry);
} spa_rl SEC(".maps");

// Rate limit per IPv6 source (exact 128-bit src)
struct rl6_key { __u8 src6[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rl6_key);
    __type(value, struct rl_entry);
} spa_rl6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} always_allow_v4 SEC(".maps");

// LPM trie for globally always-allowed IPv6 sources
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} always_allow_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROTECTED_PORTS_MAX);
    __type(key, __u16);
    __type(value, __u8);
} protected_ports_set SEC(".maps");

static __always_inline int rl_allow(__u32 src, struct spa_config *cfg) {
    struct rl_entry *e = bpf_map_lookup_elem(&spa_rl, &src);
    __u64 now = bpf_ktime_get_ns();
    __u64 rate_ns = cfg->spa_rl_rate_per_sec ? (1000000000ull / cfg->spa_rl_rate_per_sec) : 0;
    __u32 burst = cfg->spa_rl_burst ? cfg->spa_rl_burst : 1;
    if (!rate_ns) return 1;
    if (!e) {
        // Zero-initialize to satisfy older verifier (avoid reading uninit padding)
        struct rl_entry init = (struct rl_entry){};
        init.last_ts = now;
        init.tokens = burst - 1;
        bpf_map_update_elem(&spa_rl, &src, &init, BPF_ANY);
        return 1;
    }
    __u64 elapsed = now - e->last_ts;
    if (elapsed >= rate_ns) {
        __u64 add = elapsed / rate_ns;
        __u64 newt = e->tokens + add;
        e->tokens = newt > burst ? burst : (__u32)newt;
        e->last_ts = now;
    }
    if (e->tokens > 0) { e->tokens--; return 1; }
    return 0;
}

static __always_inline int parse_eth(void *data, void *data_end, __u16 *eth_proto, __u64 *offset)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    *eth_proto = eth->h_proto;
    *offset = sizeof(*eth);
    return 0;
}

SEC("xdp")
int xdp_spa(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 eth_proto;
	__u64 nh_off = 0;
	if (parse_eth(data, data_end, &eth_proto, &nh_off) < 0)
		return XDP_PASS;

    // Handle IPv4 (0x0800) and IPv6 (0x86DD). VLAN handling omitted to avoid extra headers/macros.
    if (eth_proto == bpf_htons(0x0800)) {
        struct iphdr *iph = data + nh_off;
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }
        __u32 ihl_len = (__u32)iph->ihl * 4;
        if (ihl_len < sizeof(*iph)) {
            return XDP_PASS;
        }
        void *l4 = (void *)iph + ihl_len;
        if (l4 > data_end) {
            return XDP_PASS;
        }

        __u32 cfg_key = 0;
        struct spa_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
        if (!cfg)
            return XDP_PASS;

        __u32 src = iph->saddr;
        __u8 proto = iph->protocol;

        // Allow SPA UDP packets to reach userspace
        if (proto == 17 /* UDP */) {
            struct udphdr *udph = l4;
            if ((void *)(udph + 1) > data_end)
                return XDP_PASS;
            if (udph->dest == cfg->spa_port) {
                if (!rl_allow(src, cfg)) return cfg->log_only ? XDP_PASS : XDP_DROP;
                return XDP_PASS; // SPA listener
            }
            int match = 0;
            __u16 d = udph->dest;
            __u8 *pv = bpf_map_lookup_elem(&protected_ports_set, &d);
            if (pv) match = 1;
            if (match) {
                // Enforce SPA for UDP to protected port as well
                struct lpm_v4 lkey = { .prefixlen = 32, .addr = iph->saddr };
                __u8 *av = bpf_map_lookup_elem(&always_allow_v4, &lkey);
                if (av)
                    return XDP_PASS;
                struct allowed_key akey; __builtin_memset(&akey, 0, sizeof(akey));
                akey.src = iph->saddr; akey.dport = udph->dest;
                struct allowed_entry *ent = bpf_map_lookup_elem(&allowed_ipv4, &akey);
                __u64 now = bpf_ktime_get_ns();
                if (!ent)
                    return cfg->log_only ? XDP_PASS : XDP_DROP;
                if (ent->allow_expires_at_ns != 0 && now > ent->allow_expires_at_ns) {
                    // Allow within grace regardless for UDP; re-arm idle
                    if (ent->grace_expires_at_ns == 0 || now > ent->grace_expires_at_ns)
                        return cfg->log_only ? XDP_PASS : XDP_DROP;
                    __u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
                    __u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
                    ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
                    ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
                    ent->initialized = 1;
                    return XDP_PASS;
                }
                // Normal allowed traffic extends both idle and grace windows
                __u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
                __u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
                ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
                ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
                ent->initialized = 1;
                return XDP_PASS;
            }
            return XDP_PASS;
        }

        if (proto == 6 /* TCP */) {
            struct tcphdr *tcph = l4;
            if ((void *)(tcph + 1) > data_end)
                return XDP_PASS;
            int match = 0;
            __u16 d = tcph->dest;
            __u8 *pv = bpf_map_lookup_elem(&protected_ports_set, &d);
            if (pv) match = 1;
            if (!match) return XDP_PASS;

            // Protected TCP port: enforce SPA allowlist per (src,dport)
            struct lpm_v4 lkey = { .prefixlen = 32, .addr = iph->saddr };
            __u8 *av = bpf_map_lookup_elem(&always_allow_v4, &lkey);
            if (av)
                return XDP_PASS;
            struct allowed_key akey; __builtin_memset(&akey, 0, sizeof(akey));
            akey.src = iph->saddr; akey.dport = tcph->dest;
            struct allowed_entry *ent = bpf_map_lookup_elem(&allowed_ipv4, &akey);
            __u64 now = bpf_ktime_get_ns();
            if (!ent)
                return cfg->log_only ? XDP_PASS : XDP_DROP;

            // If idle expired, allow only SYN within grace, then re-arm
            if (ent->allow_expires_at_ns != 0 && now > ent->allow_expires_at_ns) {
                if (ent->grace_expires_at_ns == 0 || now > ent->grace_expires_at_ns)
                    return cfg->log_only ? XDP_PASS : XDP_DROP;
                if (!tcph->syn)
                    return cfg->log_only ? XDP_PASS : XDP_DROP;
                __u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
                __u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
                ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
                ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
                ent->initialized = 1;
                return XDP_PASS;
            }

            // Normal allowed traffic extends both idle and grace windows
            __u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
            __u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
            ent->allow_expires_at_ns = now + idle_ns;
            ent->grace_expires_at_ns = now + grace_ns;
            ent->initialized = 1;
            return XDP_PASS;
        }

        // Other protocols
        return XDP_PASS;
    }

    if (eth_proto == bpf_htons(0x86DD)) {
        struct ipv6hdr *ip6h = data + nh_off;
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;
        __u8 nexthdr = ip6h->nexthdr;
        void *l4 = (void *)(ip6h + 1);
        if (l4 > data_end) return XDP_PASS;

        __u32 cfg_key = 0;
        struct spa_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
        if (!cfg) return XDP_PASS;

        // Rate limit key for IPv6 source
        struct rl6_key rlk; __builtin_memset(&rlk, 0, sizeof(rlk));
        __builtin_memcpy(rlk.src6, &ip6h->saddr, 16);

        // UDP
        if (nexthdr == 17) {
            struct udphdr *udph = l4;
            if ((void *)(udph + 1) > data_end) return XDP_PASS;
            if (udph->dest == cfg->spa_port) {
                // IPv6 RL
                struct rl_entry *e = bpf_map_lookup_elem(&spa_rl6, &rlk);
                __u64 now = bpf_ktime_get_ns();
                __u64 rate_ns = cfg->spa_rl_rate_per_sec ? (1000000000ull / cfg->spa_rl_rate_per_sec) : 0;
                __u32 burst = cfg->spa_rl_burst ? cfg->spa_rl_burst : 1;
                int allow = 1;
                if (rate_ns) {
                    if (!e) {
                        struct rl_entry init = (struct rl_entry){};
                        init.last_ts = now; init.tokens = burst - 1;
                        bpf_map_update_elem(&spa_rl6, &rlk, &init, BPF_ANY);
                        allow = 1;
                    } else {
                        __u64 elapsed = now - e->last_ts;
                        if (elapsed >= rate_ns) {
                            __u64 add = elapsed / rate_ns;
                            __u64 newt = e->tokens + add;
                            e->tokens = newt > burst ? burst : (__u32)newt;
                            e->last_ts = now;
                        }
                        if (e->tokens > 0) { e->tokens--; allow = 1; } else { allow = 0; }
                    }
                }
                if (!allow) return cfg->log_only ? XDP_PASS : XDP_DROP;
                return XDP_PASS;
            }
            int match = 0;
            __u16 d = udph->dest;
            __u8 *pv = bpf_map_lookup_elem(&protected_ports_set, &d);
            if (pv) match = 1;
            if (match) {
                struct lpm_v6 lkey6; __builtin_memset(&lkey6, 0, sizeof(lkey6));
                lkey6.prefixlen = 128;
                __builtin_memcpy(lkey6.addr, &ip6h->saddr, 16);
                __u8 *av6 = bpf_map_lookup_elem(&always_allow_v6, &lkey6);
                if (av6) return XDP_PASS;
                struct allowed6_key a6; __builtin_memset(&a6, 0, sizeof(a6));
                __builtin_memcpy(a6.src6, &ip6h->saddr, 16); a6.dport = udph->dest;
                struct allowed_entry *ent = bpf_map_lookup_elem(&allowed_ipv6, &a6);
                __u64 now = bpf_ktime_get_ns();
                if (!ent) return cfg->log_only ? XDP_PASS : XDP_DROP;
                if (ent->allow_expires_at_ns != 0 && now > ent->allow_expires_at_ns) {
                    if (ent->grace_expires_at_ns == 0 || now > ent->grace_expires_at_ns)
                        return cfg->log_only ? XDP_PASS : XDP_DROP;
                    __u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
                    __u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
                    ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
                    ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
                    ent->initialized = 1;
                    return XDP_PASS;
                }
                __u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
                __u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
                ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
                ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
                ent->initialized = 1;
                return XDP_PASS;
            }
            return XDP_PASS;
        }

        // TCP
        if (nexthdr == 6) {
            struct tcphdr *tcph = l4;
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;
            int match = 0;
            __u16 d = tcph->dest;
            __u8 *pv = bpf_map_lookup_elem(&protected_ports_set, &d);
            if (pv) match = 1;
            if (!match) return XDP_PASS;
            struct lpm_v6 lkey6; __builtin_memset(&lkey6, 0, sizeof(lkey6));
            lkey6.prefixlen = 128;
            __builtin_memcpy(lkey6.addr, &ip6h->saddr, 16);
            __u8 *av6 = bpf_map_lookup_elem(&always_allow_v6, &lkey6);
            if (av6) return XDP_PASS;
            struct allowed6_key a6; __builtin_memset(&a6, 0, sizeof(a6));
            __builtin_memcpy(a6.src6, &ip6h->saddr, 16); a6.dport = tcph->dest;
            struct allowed_entry *ent = bpf_map_lookup_elem(&allowed_ipv6, &a6);
            __u64 now = bpf_ktime_get_ns();
            if (!ent) return cfg->log_only ? XDP_PASS : XDP_DROP;
            if (ent->allow_expires_at_ns != 0 && now > ent->allow_expires_at_ns) {
                if (ent->grace_expires_at_ns == 0 || now > ent->grace_expires_at_ns)
                    return cfg->log_only ? XDP_PASS : XDP_DROP;
                if (!tcph->syn) return cfg->log_only ? XDP_PASS : XDP_DROP;
                __u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
                __u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
                ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
                ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
                ent->initialized = 1;
                return XDP_PASS;
            }
            __u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
            __u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
            ent->allow_expires_at_ns = now + idle_ns;
            ent->grace_expires_at_ns = now + grace_ns;
            ent->initialized = 1;
            return XDP_PASS;
        }

        return XDP_PASS;
    }

    return XDP_PASS;
}


