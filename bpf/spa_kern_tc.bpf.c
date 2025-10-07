// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "spa_common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct allowed_key);    // (src,dport)
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
    __type(key, __u32);                 // IPv4 src
    __type(value, struct rl_entry);
} spa_rl SEC(".maps");

// Rate limit per IPv6 source
struct rl6_key { __u8 src6[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rl6_key);
    __type(value, struct rl_entry);
} spa_rl6 SEC(".maps");

// LPM trie for globally always-allowed IPv4 sources
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

// Hash set of protected L4 destination ports (network byte order)
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
    if (!rate_ns) return 1; // disabled
    if (!e) {
        // Zero-initialize to satisfy older verifier (avoid reading uninit padding)
        struct rl_entry init = {0};
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

static __always_inline int load_bytes(void *dst, void *data, void *data_end, __u64 off, __u64 len)
{
	if (data + off + len > data_end) return -1;
	__builtin_memcpy(dst, data + off, len);
	return 0;
}

SEC("classifier")
int tc_spa(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr eth;
	if (load_bytes(&eth, data, data_end, 0, sizeof(eth)) < 0)
		return BPF_OK;
	// IPv4
	if (eth.h_proto == bpf_htons(0x0800)) {
		struct iphdr iph;
		if (load_bytes(&iph, data, data_end, sizeof(eth), sizeof(iph)) < 0)
			return BPF_OK;
		__u32 ihl_len = (__u32)iph.ihl * 4;
		if (ihl_len < sizeof(struct iphdr))
			return BPF_OK;

		__u32 cfg_key = 0;
		struct spa_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
		if (!cfg)
			return BPF_OK;

		__u32 src = iph.saddr;
		__u8 proto = iph.protocol;
		__u64 l4_off = sizeof(eth) + ihl_len;

		if (proto == 17 /* UDP */) {
			struct udphdr udp;
			if (load_bytes(&udp, data, data_end, l4_off, sizeof(udp)) < 0)
				return BPF_OK;
			if (udp.dest == cfg->spa_port) {
				if (!rl_allow(src, cfg)) return cfg->log_only ? BPF_OK : BPF_DROP;
				return BPF_OK; // allow SPA packet to userspace
			}
			// Bypass SPA if source is in ALWAYS_ALLOW (CIDR) list
			struct lpm_v4 lkey = { .prefixlen = 32, .addr = src };
			__u8 *av = bpf_map_lookup_elem(&always_allow_v4, &lkey);
			if (av) { return BPF_OK; }
			// Check allowlist first (exact src)
			struct allowed_key akey; __builtin_memset(&akey, 0, sizeof(akey));
			akey.src = src; akey.dport = udp.dest;
			struct allowed_entry *ent = bpf_map_lookup_elem(&allowed_ipv4, &akey);
			__u64 now = bpf_ktime_get_ns();
			if (ent) {
				if (ent->allow_expires_at_ns != 0 && now > ent->allow_expires_at_ns) {
					if (ent->grace_expires_at_ns == 0 || now > ent->grace_expires_at_ns) { return cfg->log_only ? BPF_OK : BPF_DROP; }
					__u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
					__u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
					ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
					ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
					ent->initialized = 1;
					return BPF_OK;
				}
				__u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
				__u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
				ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
				ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
				ent->initialized = 1;
				return BPF_OK;
			}
			// Not on allowlist: drop only if port is protected; else pass
			__u16 d = udp.dest;
			__u8 *pv = bpf_map_lookup_elem(&protected_ports_set, &d);
			if (pv) { return cfg->log_only ? BPF_OK : BPF_DROP; }
			return BPF_OK;
		}

		if (proto == 6 /* TCP */) {
			struct tcphdr tcp;
			if (load_bytes(&tcp, data, data_end, l4_off, sizeof(tcp)) < 0)
				return BPF_OK;
			// Bypass SPA if source is in ALWAYS_ALLOW (CIDR) list
			struct lpm_v4 lkey = { .prefixlen = 32, .addr = src };
			__u8 *av = bpf_map_lookup_elem(&always_allow_v4, &lkey);
			if (av) { return BPF_OK; }

			// Check allowlist first (exact src)
			struct allowed_key akey; __builtin_memset(&akey, 0, sizeof(akey));
			akey.src = src; akey.dport = tcp.dest;
			struct allowed_entry *ent = bpf_map_lookup_elem(&allowed_ipv4, &akey);
			__u64 now = bpf_ktime_get_ns();
			if (ent) {
				if (ent->allow_expires_at_ns != 0 && now > ent->allow_expires_at_ns) {
					if (ent->grace_expires_at_ns == 0 || now > ent->grace_expires_at_ns) { return cfg->log_only ? BPF_OK : BPF_DROP; }
					if (!tcp.syn) { return cfg->log_only ? BPF_OK : BPF_DROP; }
					__u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
					__u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
					ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
					ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
					ent->initialized = 1;
					return BPF_OK;
				}

				__u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
				__u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
				ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
				ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
				ent->initialized = 1;
				return BPF_OK;
			}

			// Not on allowlist: drop only if port is protected; else pass
			__u16 d = tcp.dest;
			__u8 *pv = bpf_map_lookup_elem(&protected_ports_set, &d);
			if (pv) { return cfg->log_only ? BPF_OK : BPF_DROP; }
			return BPF_OK;
		}

		return BPF_OK;
	}

	if (eth.h_proto == bpf_htons(0x86DD)) {
		// IPv6
		struct ipv6hdr ip6h;
		if (load_bytes(&ip6h, data, data_end, sizeof(eth), sizeof(ip6h)) < 0)
			return BPF_OK;
		__u8 nexthdr = ip6h.nexthdr;
		__u64 l4_off = sizeof(eth) + sizeof(ip6h);

		__u32 cfg_key = 0;
		struct spa_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
		if (!cfg) return BPF_OK;

		struct rl6_key rlk; __builtin_memset(&rlk, 0, sizeof(rlk));
		__builtin_memcpy(rlk.src6, &ip6h.saddr, 16);

		if (nexthdr == 17) {
			struct udphdr udp;
			if (load_bytes(&udp, data, data_end, l4_off, sizeof(udp)) < 0) return BPF_OK;
			if (udp.dest == cfg->spa_port) {
				// RL for IPv6
				struct rl_entry *e = bpf_map_lookup_elem(&spa_rl6, &rlk);
				__u64 now = bpf_ktime_get_ns();
				__u64 rate_ns = cfg->spa_rl_rate_per_sec ? (1000000000ull / cfg->spa_rl_rate_per_sec) : 0;
				__u32 burst = cfg->spa_rl_burst ? cfg->spa_rl_burst : 1;
				int allow = 1;
				if (rate_ns) {
					if (!e) {
						struct rl_entry init = {0}; init.last_ts = now; init.tokens = burst - 1;
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
				if (!allow) return cfg->log_only ? BPF_OK : BPF_DROP;
				return BPF_OK;
			}
			// Bypass SPA if source is in ALWAYS_ALLOW (CIDR) list
			struct lpm_v6 lkey6; __builtin_memset(&lkey6, 0, sizeof(lkey6));
			lkey6.prefixlen = 128; __builtin_memcpy(lkey6.addr, &ip6h.saddr, 16);
			__u8 *av6 = bpf_map_lookup_elem(&always_allow_v6, &lkey6);
			if (av6) { return BPF_OK; }
			// Check allowlist first (exact src6)
			struct allowed6_key a6; __builtin_memset(&a6, 0, sizeof(a6));
			__builtin_memcpy(a6.src6, &ip6h.saddr, 16); a6.dport = udp.dest;
			struct allowed_entry *ent = bpf_map_lookup_elem(&allowed_ipv6, &a6);
			__u64 now = bpf_ktime_get_ns();
			if (ent) {
				if (ent->allow_expires_at_ns != 0 && now > ent->allow_expires_at_ns) {
					if (ent->grace_expires_at_ns == 0 || now > ent->grace_expires_at_ns) { return cfg->log_only ? BPF_OK : BPF_DROP; }
					__u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
					__u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
					ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
					ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
					ent->initialized = 1;
					return BPF_OK;
				}
				__u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
				__u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
				ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
				ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
				ent->initialized = 1;
				return BPF_OK;
			}
			// Not on allowlist: drop only if port is protected; else pass
			__u16 d6 = udp.dest;
			__u8 *pv6 = bpf_map_lookup_elem(&protected_ports_set, &d6);
			if (pv6) { return cfg->log_only ? BPF_OK : BPF_DROP; }
			return BPF_OK;
		}

		if (nexthdr == 6) {
			struct tcphdr tcp;
			if (load_bytes(&tcp, data, data_end, l4_off, sizeof(tcp)) < 0) return BPF_OK;
			struct lpm_v6 lkey6; __builtin_memset(&lkey6, 0, sizeof(lkey6));
			lkey6.prefixlen = 128; __builtin_memcpy(lkey6.addr, &ip6h.saddr, 16);
			__u8 *av6 = bpf_map_lookup_elem(&always_allow_v6, &lkey6);
			if (av6) { return BPF_OK; }
			struct allowed6_key a6; __builtin_memset(&a6, 0, sizeof(a6));
			__builtin_memcpy(a6.src6, &ip6h.saddr, 16); a6.dport = tcp.dest;
			struct allowed_entry *ent = bpf_map_lookup_elem(&allowed_ipv6, &a6);
			__u64 now = bpf_ktime_get_ns();
			if (ent) {
				if (ent->allow_expires_at_ns != 0 && now > ent->allow_expires_at_ns) {
					if (ent->grace_expires_at_ns == 0 || now > ent->grace_expires_at_ns) { return cfg->log_only ? BPF_OK : BPF_DROP; }
					if (!tcp.syn) { return cfg->log_only ? BPF_OK : BPF_DROP; }
					__u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
					__u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
					ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
					ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
					ent->initialized = 1;
					return BPF_OK;
				}
				__u64 idle_ns = ent->idle_extend_ns_override ? ent->idle_extend_ns_override : cfg->idle_extend_ns;
				__u64 grace_ns = ent->grace_ns_override ? ent->grace_ns_override : cfg->post_disconnect_grace_ns;
				ent->allow_expires_at_ns = (idle_ns == (__u64)-1) ? (__u64)-1 : now + idle_ns;
				ent->grace_expires_at_ns = (grace_ns == (__u64)-1) ? (__u64)-1 : now + grace_ns;
				ent->initialized = 1;
				return BPF_OK;
			}
			__u16 d6 = tcp.dest;
			__u8 *pv6 = bpf_map_lookup_elem(&protected_ports_set, &d6);
			if (pv6) { return cfg->log_only ? BPF_OK : BPF_DROP; }
			return BPF_OK;
		}

		return BPF_OK;
	}

	return BPF_OK;
}



