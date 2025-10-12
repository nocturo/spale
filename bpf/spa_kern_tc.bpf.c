// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "spa_common.h"
#include "spa_bpf_common.h"

char LICENSE[] SEC("license") = "GPL";

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
                if (!rl_allow_v4(src, cfg)) return cfg->log_only ? BPF_OK : BPF_DROP;
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
                if (!rl_allow6(&ip6h.saddr, cfg)) return cfg->log_only ? BPF_OK : BPF_DROP;
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



