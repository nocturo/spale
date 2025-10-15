// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "spa_common.h"
#include "always_allow.h"

unsigned always_allow_parse_and_apply(const char *env_value,
                                      int map_fd_v4,
                                      int lpm_fd_v4,
                                      int map_fd_v6,
                                      int lpm_fd_v6,
                                      const struct spa_config *cfg)
{
    if (!env_value || !*env_value) return 0;
    unsigned added = 0;
    const char *p = env_value;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ',') p++;
        size_t len = (size_t)(p - start);
        if (len > 0 && len < 128) {
            char ipbuf[128];
            memcpy(ipbuf, start, len);
            ipbuf[len] = '\0';

            char *slash = strchr(ipbuf, '/');
            struct in_addr a4;
            int is_v4_host = 0, is_v4_cidr = 0;
            if (slash) {
                *slash = '\0';
                int prefix = atoi(slash + 1);
                if (prefix >= 0 && prefix <= 32 && inet_aton(ipbuf, &a4)) {
                    is_v4_cidr = 1;
                    if (lpm_fd_v4 >= 0) {
                        struct lpm_v4 lk = { .prefixlen = (unsigned)prefix, .addr = a4.s_addr };
                        __u8 one = 1;
                        (void)bpf_map_update_elem(lpm_fd_v4, &lk, &one, BPF_ANY);
                        added++;
                    }
                }
                *slash = '/';
            } else if (inet_aton(ipbuf, &a4)) {
                is_v4_host = 1;
                if (lpm_fd_v4 >= 0) {
                    struct lpm_v4 lk; memset(&lk, 0, sizeof(lk));
                    lk.prefixlen = 32; lk.addr = a4.s_addr;
                    __u8 one = 1;
                    (void)bpf_map_update_elem(lpm_fd_v4, &lk, &one, BPF_ANY);
                }
                struct allowed_entry val; memset(&val, 0, sizeof(val));
                val.allow_expires_at_ns = (unsigned long long)(~0ULL);
                val.grace_expires_at_ns = (unsigned long long)(~0ULL);
                val.initialized = 1;
                if (cfg && cfg->num_ports > 0 && map_fd_v4 >= 0) {
                    for (unsigned int i = 0; i < cfg->num_ports; i++) {
                        struct allowed_key k; memset(&k, 0, sizeof(k));
                        k.src = a4.s_addr; k.dport = cfg->protected_ports[i];
                        (void)bpf_map_update_elem(map_fd_v4, &k, &val, BPF_ANY);
                        added++;
                    }
                }
            }

            if (!(is_v4_host || is_v4_cidr)) {
                struct in6_addr a6;
                if (slash) {
                    *slash = '\0';
                    int prefix = atoi(slash + 1);
                    if (prefix >= 0 && prefix <= 128 && inet_pton(AF_INET6, ipbuf, &a6) == 1) {
                        if (lpm_fd_v6 >= 0) {
                            struct lpm_v6 lk; memset(&lk, 0, sizeof(lk));
                            lk.prefixlen = (unsigned)prefix;
                            memcpy(lk.addr, &a6, 16);
                            __u8 one = 1;
                            (void)bpf_map_update_elem(lpm_fd_v6, &lk, &one, BPF_ANY);
                            added++;
                        }
                    }
                    *slash = '/';
                } else if (inet_pton(AF_INET6, ipbuf, &a6) == 1) {
                    if (lpm_fd_v6 >= 0) {
                        struct lpm_v6 lk; memset(&lk, 0, sizeof(lk));
                        lk.prefixlen = 128; memcpy(lk.addr, &a6, 16);
                        __u8 one = 1;
                        (void)bpf_map_update_elem(lpm_fd_v6, &lk, &one, BPF_ANY);
                    }
                    struct allowed_entry val; memset(&val, 0, sizeof(val));
                    val.allow_expires_at_ns = (unsigned long long)(~0ULL);
                    val.grace_expires_at_ns = (unsigned long long)(~0ULL);
                    val.initialized = 1;
                    if (cfg && cfg->num_ports > 0 && map_fd_v6 >= 0) {
                        for (unsigned int i = 0; i < cfg->num_ports; i++) {
                            struct allowed6_key k; memset(&k, 0, sizeof(k));
                            memcpy(k.src6, &a6, 16);
                            k.dport = cfg->protected_ports[i];
                            (void)bpf_map_update_elem(map_fd_v6, &k, &val, BPF_ANY);
                            added++;
                        }
                    }
                }
            }
        }
        if (*p == ',') p++;
    }
    return added;
}


