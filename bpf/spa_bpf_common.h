// SPDX-License-Identifier: GPL-2.0-only
#ifndef SPA_BPF_COMMON_H
#define SPA_BPF_COMMON_H

struct rl_entry { __u64 last_ts; __u32 tokens; };

struct rl6_key { __u8 src6[16]; };

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct allowed_key);
	__type(value, struct allowed_entry);
#ifdef SPALE_PIN_BY_NAME
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
} allowed_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct allowed6_key);
	__type(value, struct allowed_entry);
#ifdef SPALE_PIN_BY_NAME
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
} allowed_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct spa_config);
#ifdef SPALE_PIN_BY_NAME
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct rl_entry);
#ifdef SPALE_PIN_BY_NAME
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
} spa_rl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct rl6_key);
	__type(value, struct rl_entry);
#ifdef SPALE_PIN_BY_NAME
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
} spa_rl6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct lpm_v4);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
#ifdef SPALE_PIN_BY_NAME
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
} always_allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct lpm_v6);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
#ifdef SPALE_PIN_BY_NAME
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
} always_allow_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROTECTED_PORTS_MAX);
	__type(key, __u16);
	__type(value, __u8);
#ifdef SPALE_PIN_BY_NAME
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
} protected_ports_set SEC(".maps");

static __always_inline int rl_allow_v4(__u32 src, const struct spa_config *cfg)
{
	struct rl_entry *e = bpf_map_lookup_elem(&spa_rl, &src);
	__u64 now = bpf_ktime_get_ns();
	__u64 rate_ns = cfg->spa_rl_rate_per_sec ? (1000000000ull / cfg->spa_rl_rate_per_sec) : 0;
	__u32 burst = cfg->spa_rl_burst ? cfg->spa_rl_burst : 1;
	if (!rate_ns) return 1;
	if (!e) {
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

static __always_inline int rl_allow6(const void *src6, const struct spa_config *cfg)
{
	struct rl6_key rlk; __builtin_memset(&rlk, 0, sizeof(rlk));
	__builtin_memcpy(rlk.src6, src6, 16);
	struct rl_entry *e = bpf_map_lookup_elem(&spa_rl6, &rlk);
	__u64 now = bpf_ktime_get_ns();
	__u64 rate_ns = cfg->spa_rl_rate_per_sec ? (1000000000ull / cfg->spa_rl_rate_per_sec) : 0;
	__u32 burst = cfg->spa_rl_burst ? cfg->spa_rl_burst : 1;
	if (!rate_ns) return 1;
	if (!e) {
		struct rl_entry init = (struct rl_entry){};
		init.last_ts = now;
		init.tokens = burst - 1;
		bpf_map_update_elem(&spa_rl6, &rlk, &init, BPF_ANY);
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

#endif /* SPA_BPF_COMMON_H */


