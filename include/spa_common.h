// SPDX-License-Identifier: MIT
#ifndef SPA_COMMON_H
#define SPA_COMMON_H

struct spa_config {
    unsigned short spa_port;                     /* network byte order */
    unsigned long long idle_extend_ns;           /* how long to extend on any packet */
    unsigned long long post_disconnect_grace_ns; /* grace window after FIN/RST */
    unsigned int spa_rl_rate_per_sec;            /* SPA UDP rate limit (per src) */
    unsigned int spa_rl_burst;                   /* SPA UDP burst tokens */
    unsigned int num_ports;                      /* number of entries in protected_ports[] */
#define PROTECTED_PORTS_MAX 16
    unsigned short protected_ports[PROTECTED_PORTS_MAX]; /* network byte order */
    unsigned int log_only;                       /* when non-zero, never drop traffic; log-only */
};

struct allowed_entry {
	unsigned long long allow_expires_at_ns; /* 0 means unset/pending init */
	unsigned char      initialized;         /* 0 until first packet seen */
	unsigned long long grace_expires_at_ns; /* allow SYN/UDP within grace */
	/* Optional per-client overrides. 0 => use global cfg values */
	unsigned long long idle_extend_ns_override;
	unsigned long long grace_ns_override;
};

struct allowed_key {
	unsigned int src;   /* IPv4 src in network byte order */
	unsigned short dport; /* L4 dest port in network byte order */
};

/* IPv6 allowlist key: (src6, dport) */
struct allowed6_key {
	unsigned char src6[16];  /* IPv6 src in network byte order */
	unsigned short dport;    /* L4 dest port in network byte order */
};

/* LPM trie key for IPv4 */
struct lpm_v4 {
	unsigned int prefixlen; /* number of significant bits in addr */
	unsigned int addr;      /* IPv4 address in network byte order */
};

/* LPM trie key for IPv6 */
struct lpm_v6 {
	unsigned int prefixlen; /* number of significant bits in addr */
	unsigned char addr[16]; /* IPv6 address in network byte order */
};

#endif /* SPA_COMMON_H */


