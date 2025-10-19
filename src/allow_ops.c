// SPDX-License-Identifier: MIT
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

#include "spa_common.h"
#include "allow_ops.h"
#include "logger.h"

unsigned authorize_ipv4(int map_fd,
                        __u32 src_ip,
                        const struct spa_config *cfg,
                        const uint16_t *client_ports,
                        unsigned client_n,
                        const struct allowed_entry *val)
{
    unsigned wrote = 0;
    static int warned = 0;
    if (client_n > 0) {
        for (unsigned i = 0; i < client_n; i++) {
            struct allowed_key ak; memset(&ak, 0, sizeof(ak));
            ak.src = src_ip; ak.dport = htons(client_ports[i]);
            if (bpf_map_update_elem(map_fd, &ak, val, BPF_ANY) == 0) wrote++;
            else if (!warned) { LOG_ERROR("bpf_map_update_elem failed (v4, port=%u): %s. Consider CAP_BPF or kernel.unprivileged_bpf_disabled.", (unsigned)client_ports[i], strerror(errno)); warned = 1; }
        }
    } else if (cfg->num_ports > 0) {
        for (unsigned i = 0; i < cfg->num_ports; i++) {
            struct allowed_key ak; memset(&ak, 0, sizeof(ak));
            ak.src = src_ip; ak.dport = cfg->protected_ports[i];
            if (bpf_map_update_elem(map_fd, &ak, val, BPF_ANY) == 0) wrote++;
            else if (!warned) { LOG_ERROR("bpf_map_update_elem failed (v4, port=%u): %s. Consider CAP_BPF or kernel.unprivileged_bpf_disabled.", (unsigned)ntohs(cfg->protected_ports[i]), strerror(errno)); warned = 1; }
        }
    }
    return wrote;
}

unsigned authorize_ipv6(int map_fd,
                        const struct in6_addr *src6,
                        const struct spa_config *cfg,
                        const uint16_t *client_ports,
                        unsigned client_n,
                        const struct allowed_entry *val)
{
    unsigned wrote = 0;
    static int warned = 0;
    if (client_n > 0) {
        for (unsigned i = 0; i < client_n; i++) {
            struct allowed6_key ak; memset(&ak, 0, sizeof(ak));
            memcpy(ak.src6, src6, 16); ak.dport = htons(client_ports[i]);
            if (bpf_map_update_elem(map_fd, &ak, val, BPF_ANY) == 0) wrote++;
            else if (!warned) { LOG_ERROR("bpf_map_update_elem failed (v6, port=%u): %s. Consider CAP_BPF or kernel.unprivileged_bpf_disabled.", (unsigned)client_ports[i], strerror(errno)); warned = 1; }
        }
    } else if (cfg->num_ports > 0) {
        for (unsigned i = 0; i < cfg->num_ports; i++) {
            struct allowed6_key ak; memset(&ak, 0, sizeof(ak));
            memcpy(ak.src6, src6, 16); ak.dport = cfg->protected_ports[i];
            if (bpf_map_update_elem(map_fd, &ak, val, BPF_ANY) == 0) wrote++;
            else if (!warned) { LOG_ERROR("bpf_map_update_elem failed (v6, port=%u): %s. Consider CAP_BPF or kernel.unprivileged_bpf_disabled.", (unsigned)ntohs(cfg->protected_ports[i]), strerror(errno)); warned = 1; }
        }
    }
    return wrote;
}

unsigned authorize_addr(int af,
                        int map_fd_v4,
                        int map_fd_v6,
                        const void *src_addr,
                        const struct spa_config *cfg,
                        const uint16_t *client_ports,
                        unsigned client_n,
                        const struct allowed_entry *val)
{
    if (af == AF_INET && src_addr) {
        __u32 src_ip = *(__u32 *)src_addr;
        return authorize_ipv4(map_fd_v4, src_ip, cfg, client_ports, client_n, val);
    } else if (af == AF_INET6 && src_addr) {
        const struct in6_addr *src6 = (const struct in6_addr *)src_addr;
        return authorize_ipv6(map_fd_v6, src6, cfg, client_ports, client_n, val);
    }
    return 0;
}


