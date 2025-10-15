// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "spa_common.h"
#include "mgmt_server.h"

// Minimal mirror types for ratelimit map values/keys (userspace only)
struct rl_entry { unsigned long long last_ts; unsigned int tokens; };
struct rl6_key { unsigned char src6[16]; };

static void format_timestamp(unsigned long long ns, char *buf, size_t bufsize)
{
    if (ns == (unsigned long long)(~0ULL)) {
        snprintf(buf, bufsize, "never");
        return;
    }
    
    // Convert monotonic nanoseconds to real time
    struct timespec now_real, now_mono;
    clock_gettime(CLOCK_REALTIME, &now_real);
    clock_gettime(CLOCK_MONOTONIC, &now_mono);
    
    // Calculate the offset between real time and monotonic time
    unsigned long long mono_now_ns = (unsigned long long)now_mono.tv_sec * 1000000000ULL + (unsigned long long)now_mono.tv_nsec;
    unsigned long long real_now_ns = (unsigned long long)now_real.tv_sec * 1000000000ULL + (unsigned long long)now_real.tv_nsec;
    unsigned long long offset_ns = real_now_ns - mono_now_ns;
    
    // Convert the stored monotonic timestamp to real time
    unsigned long long real_ns = ns + offset_ns;
    time_t sec = (time_t)(real_ns / 1000000000ULL);
    
    struct tm *tm_info = localtime(&sec);
    if (tm_info) {
        strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%S", tm_info);
    } else {
        snprintf(buf, bufsize, "invalid");
    }
}

static unsigned parse_ports_csv(const char *csv, uint16_t *out_ports, unsigned max_out)
{
    if (!csv || !*csv || !out_ports || max_out == 0) return 0;
    unsigned count = 0;
    const char *p = csv;
    while (*p && count < max_out) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        unsigned v = 0;
        while (*p >= '0' && *p <= '9') { v = v * 10 + (unsigned)(*p - '0'); p++; }
        if (v > 0 && v <= 65535) out_ports[count++] = (uint16_t)v;
        while (*p && *p != ',') p++;
    }
    return count;
}

int mgmt_server_handle(int mgmt_fd,
                       const struct spa_config *cfg,
                       int map_fd_v4,
                       int map_fd_v6,
                       int map_always_v4,
                       int map_always_v6,
                       int map_ports_set,
                       int map_config,
                       int map_rl_v4,
                       int map_rl_v6)
{
    if (mgmt_fd < 0) return 0;
    char buf[256];
    struct sockaddr_un from; socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(mgmt_fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &flen);
    if (n <= 0) return 0;
    buf[n] = '\0';

    char *cmd = buf; while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (strncmp(cmd, "list", 4) == 0) {
        char *arg = cmd + 4; while (*arg == ' ' || *arg == '\t') arg++;
        if (strncmp(arg, "authorized", 10) == 0) {
            if (map_fd_v4 >= 0) {
                struct allowed_key k, nx; struct allowed_entry v; int first = 1; memset(&k, 0, sizeof(k));
                while (bpf_map_get_next_key(map_fd_v4, first ? NULL : &k, &nx) == 0) {
                    first = 0;
                    if (bpf_map_lookup_elem(map_fd_v4, &nx, &v) == 0) {
                        struct in_addr a; a.s_addr = nx.src; char ip[INET_ADDRSTRLEN];
                        const char *s = inet_ntop(AF_INET, &a, ip, sizeof(ip));
                        char allow_time[32], grace_time[32];
                        format_timestamp(v.allow_expires_at_ns, allow_time, sizeof(allow_time));
                        format_timestamp(v.grace_expires_at_ns, grace_time, sizeof(grace_time));
                        char line[256];
                        snprintf(line, sizeof(line), "%s:%u allow=%s grace=%s init=%u\n", s ? s : "<v4>", (unsigned)ntohs(nx.dport), allow_time, grace_time, (unsigned)v.initialized);
                        (void)sendto(mgmt_fd, line, strlen(line), 0, (struct sockaddr *)&from, flen);
                    }
                    k = nx;
                }
            }
            if (map_fd_v6 >= 0) {
                struct allowed6_key k6, nx6; struct allowed_entry v; int first = 1; memset(&k6, 0, sizeof(k6));
                while (bpf_map_get_next_key(map_fd_v6, first ? NULL : &k6, &nx6) == 0) {
                    first = 0;
                    if (bpf_map_lookup_elem(map_fd_v6, &nx6, &v) == 0) {
                        char ip[INET6_ADDRSTRLEN]; const char *s = inet_ntop(AF_INET6, nx6.src6, ip, sizeof(ip));
                        char allow_time[32], grace_time[32];
                        format_timestamp(v.allow_expires_at_ns, allow_time, sizeof(allow_time));
                        format_timestamp(v.grace_expires_at_ns, grace_time, sizeof(grace_time));
                        char line[256];
                        snprintf(line, sizeof(line), "[%s]:%u allow=%s grace=%s init=%u\n", s ? s : "<v6>", (unsigned)ntohs(nx6.dport), allow_time, grace_time, (unsigned)v.initialized);
                        (void)sendto(mgmt_fd, line, strlen(line), 0, (struct sockaddr *)&from, flen);
                    }
                    k6 = nx6;
                }
            }
        } else if (strncmp(arg, "allowlist", 9) == 0) {
            if (map_always_v4 >= 0) {
                struct lpm_v4 k, nx; __u8 vv; int first = 1; memset(&k, 0, sizeof(k));
                while (bpf_map_get_next_key(map_always_v4, first ? NULL : &k, &nx) == 0) {
                    first = 0;
                    if (bpf_map_lookup_elem(map_always_v4, &nx, &vv) == 0) {
                        struct in_addr a; a.s_addr = nx.addr; char ip[INET_ADDRSTRLEN];
                        const char *s = inet_ntop(AF_INET, &a, ip, sizeof(ip));
                        char line[128]; snprintf(line, sizeof(line), "%s/%u\n", s ? s : "<v4>", nx.prefixlen);
                        (void)sendto(mgmt_fd, line, strlen(line), 0, (struct sockaddr *)&from, flen);
                    }
                    k = nx;
                }
            }
            if (map_always_v6 >= 0) {
                struct lpm_v6 k6, nx6; __u8 vv; int first = 1; memset(&k6, 0, sizeof(k6));
                while (bpf_map_get_next_key(map_always_v6, first ? NULL : &k6, &nx6) == 0) {
                    first = 0;
                    if (bpf_map_lookup_elem(map_always_v6, &nx6, &vv) == 0) {
                        char ip[INET6_ADDRSTRLEN]; const char *s = inet_ntop(AF_INET6, nx6.addr, ip, sizeof(ip));
                        char line[144]; snprintf(line, sizeof(line), "%s/%u\n", s ? s : "<v6>", nx6.prefixlen);
                        (void)sendto(mgmt_fd, line, strlen(line), 0, (struct sockaddr *)&from, flen);
                    }
                    k6 = nx6;
                }
            }
        } else if (strncmp(arg, "ports", 5) == 0) {
            if (map_ports_set >= 0) {
                __u16 k = 0, nx = 0; __u8 v; int first = 1;
                while (bpf_map_get_next_key(map_ports_set, first ? NULL : &k, &nx) == 0) {
                    first = 0;
                    if (bpf_map_lookup_elem(map_ports_set, &nx, &v) == 0) {
                        char line[64]; snprintf(line, sizeof(line), "%u\n", (unsigned)ntohs(nx));
                        (void)sendto(mgmt_fd, line, strlen(line), 0, (struct sockaddr *)&from, flen);
                    }
                    k = nx;
                }
            }
        } else if (strncmp(arg, "ratelimit", 9) == 0 || strncmp(arg, "rl", 2) == 0) {
            if (map_config >= 0) { __u32 k0 = 0; struct spa_config cfgv; if (bpf_map_lookup_elem(map_config, &k0, &cfgv) == 0) { char line[128]; snprintf(line, sizeof(line), "cfg_rl_rate_per_sec=%u cfg_rl_burst=%u\n", cfgv.spa_rl_rate_per_sec, cfgv.spa_rl_burst); (void)sendto(mgmt_fd, line, strlen(line), 0, (struct sockaddr *)&from, flen); } }
            if (map_rl_v4 >= 0) {
                __u32 k = 0, nx = 0; struct rl_entry v; int first = 1;
                while (bpf_map_get_next_key(map_rl_v4, first ? NULL : &k, &nx) == 0) {
                    first = 0;
                    if (bpf_map_lookup_elem(map_rl_v4, &nx, &v) == 0) {
                        struct in_addr a; a.s_addr = nx; char ip[INET_ADDRSTRLEN]; const char *s = inet_ntop(AF_INET, &a, ip, sizeof(ip));
                        char line[160]; snprintf(line, sizeof(line), "%s tokens=%u last_ns=%llu\n", s ? s : "<v4>", v.tokens, (unsigned long long)v.last_ts);
                        (void)sendto(mgmt_fd, line, strlen(line), 0, (struct sockaddr *)&from, flen);
                    }
                    k = nx;
                }
            }
            if (map_rl_v6 >= 0) {
                struct rl6_key k6, nx6; struct rl_entry v; int first = 1; memset(&k6, 0, sizeof(k6));
                while (bpf_map_get_next_key(map_rl_v6, first ? NULL : &k6, &nx6) == 0) {
                    first = 0;
                    if (bpf_map_lookup_elem(map_rl_v6, &nx6, &v) == 0) {
                        char ip[INET6_ADDRSTRLEN]; const char *s = inet_ntop(AF_INET6, nx6.src6, ip, sizeof(ip));
                        char line[176]; snprintf(line, sizeof(line), "[%s] tokens=%u last_ns=%llu\n", s ? s : "<v6>", v.tokens, (unsigned long long)v.last_ts);
                        (void)sendto(mgmt_fd, line, strlen(line), 0, (struct sockaddr *)&from, flen);
                    }
                    k6 = nx6;
                }
            }
        }
        static const char endm[] = "END\n"; (void)sendto(mgmt_fd, endm, sizeof(endm) - 1, 0, (struct sockaddr *)&from, flen);
        return 0;
    } else if (strncmp(cmd, "allowlist", 9) == 0) {
        char *arg = cmd + 9; while (*arg == ' ' || *arg == '\t') arg++;
        int is_add = 0, is_del = 0;
        if (strncmp(arg, "add", 3) == 0) { is_add = 1; arg += 3; }
        else if (strncmp(arg, "del", 3) == 0 || strncmp(arg, "rm", 2) == 0) { is_del = 1; arg += 3; }
        while (*arg == ' ' || *arg == '\t') arg++;
        char tok[128]; size_t tl = 0; while (*arg && *arg != '\n' && tl + 1 < sizeof(tok)) tok[tl++] = *arg++;
        tok[tl] = '\0';
        if (tok[0]) {
            char bufip[128]; strncpy(bufip, tok, sizeof(bufip) - 1); bufip[sizeof(bufip) - 1] = '\0';
            // Handle IPv6 bracket notation [2001:db8::1] or [2001:db8::1]/64
            size_t buflen = strlen(bufip);
            if (buflen > 2 && bufip[0] == '[' && bufip[buflen-1] == ']') {
                memmove(bufip, bufip + 1, buflen - 2);
                bufip[buflen - 2] = '\0';
            }
            char *slash = strchr(bufip, '/'); int prefix = -1;
            struct in_addr a4; struct in6_addr a6; int is_v4 = 0, is_v6 = 0;
            if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
            if (inet_aton(bufip, &a4)) { is_v4 = 1; if (prefix < 0) prefix = 32; }
            else if (inet_pton(AF_INET6, bufip, &a6) == 1) { is_v6 = 1; if (prefix < 0) prefix = 128; }
            if (is_add) {
                __u8 one = 1;
                int added = 0;
                if (is_v4 && map_always_v4 >= 0) { struct lpm_v4 k = { .prefixlen = (unsigned)prefix, .addr = a4.s_addr }; if (bpf_map_update_elem(map_always_v4, &k, &one, BPF_ANY) == 0) added++; }
                if (is_v6 && map_always_v6 >= 0) { struct lpm_v6 k6; memset(&k6, 0, sizeof(k6)); k6.prefixlen = (unsigned)prefix; memcpy(k6.addr, &a6, 16); if (bpf_map_update_elem(map_always_v6, &k6, &one, BPF_ANY) == 0) added++; }
                char msg[256]; snprintf(msg, sizeof(msg), "Added %s/%d to allowlist (%d entries)\n", tok, prefix, added); (void)sendto(mgmt_fd, msg, strlen(msg), 0, (struct sockaddr *)&from, flen);
            } else if (is_del) {
                int removed = 0;
                if (is_v4 && map_always_v4 >= 0) { struct lpm_v4 k = { .prefixlen = (unsigned)prefix, .addr = a4.s_addr }; if (bpf_map_delete_elem(map_always_v4, &k) == 0) removed++; }
                if (is_v6 && map_always_v6 >= 0) { struct lpm_v6 k6; memset(&k6, 0, sizeof(k6)); k6.prefixlen = (unsigned)prefix; memcpy(k6.addr, &a6, 16); if (bpf_map_delete_elem(map_always_v6, &k6) == 0) removed++; }
                char msg[256]; snprintf(msg, sizeof(msg), "Removed %s/%d from allowlist (%d entries)\n", tok, prefix, removed); (void)sendto(mgmt_fd, msg, strlen(msg), 0, (struct sockaddr *)&from, flen);
            }
        } else {
            static const char errm[] = "ERR invalid allowlist cmd\nEND\n"; (void)sendto(mgmt_fd, errm, sizeof(errm) - 1, 0, (struct sockaddr *)&from, flen);
        }
        return 0;
    } else if (strncmp(cmd, "authorize", 9) == 0) {
        char *arg = cmd + 9;
        while (*arg == ' ' || *arg == '\t') arg++;
        int is_add = 0, is_del = 0;
        if (strncmp(arg, "add", 3) == 0) { is_add = 1; arg += 3; }
        else if (strncmp(arg, "del", 3) == 0 || strncmp(arg, "rm", 2) == 0) { is_del = 1; arg += 3; }
        const char *ipstr = NULL; const char *ip_end = NULL; const char *ports_csv = NULL; long idle_sec = 0, grace_sec = 0; int have_idle = 0, have_grace = 0; char ipbuf[INET6_ADDRSTRLEN + 1]; ipbuf[0] = '\0';
        while (*arg) {
            while (*arg == ' ' || *arg == '\t') arg++;
            if (strncmp(arg, "--ip", 4) == 0) {
                arg += 4; while (*arg == ' ' || *arg == '\t') arg++;
                if (*arg == '\0') break;
                if (*arg == '"') { arg++; }
                ipstr = arg;
                while (*arg && *arg != ' ' && *arg != '\t' && *arg != '\n') arg++;
                ip_end = arg;
            }
            else if (strncmp(arg, "--ports", 7) == 0) { arg += 7; while (*arg == ' ' || *arg == '\t') arg++; ports_csv = arg; while (*arg && *arg != '\n') arg++; }
            else if (strncmp(arg, "--idle-sec", 10) == 0) { arg += 10; while (*arg == ' ' || *arg == '\t') arg++; idle_sec = strtol(arg, NULL, 10); have_idle = 1; while (*arg && *arg != ' ' && *arg != '\t' && *arg != '\n') arg++; }
            else if (strncmp(arg, "--grace-sec", 11) == 0) { arg += 11; while (*arg == ' ' || *arg == '\t') arg++; grace_sec = strtol(arg, NULL, 10); have_grace = 1; while (*arg && *arg != ' ' && *arg != '\t' && *arg != '\n') arg++; }
            else { break; }
        }
            if (ipstr && ipbuf[0] == '\0') {
                const char *iend = ip_end;
                if (!iend) { iend = ipstr; while (*iend && *iend != ' ' && *iend != '\t' && *iend != '\n') iend++; }
                size_t ilen = (size_t)(iend > ipstr ? (size_t)(iend - ipstr) : 0);
                if (ilen >= sizeof(ipbuf)) ilen = sizeof(ipbuf) - 1;
                if (ilen > 0) { 
                    memcpy(ipbuf, ipstr, ilen); ipbuf[ilen] = '\0'; 
                    // Handle IPv6 bracket notation [2001:db8::1]
                    if (ipbuf[0] == '[' && ilen > 2 && ipbuf[ilen-1] == ']') {
                        memmove(ipbuf, ipbuf + 1, ilen - 2);
                        ipbuf[ilen - 2] = '\0';
                    }
                }
            }
        if (!ipstr) { static const char errm[] = "ERR missing --ip\nEND\n"; (void)sendto(mgmt_fd, errm, sizeof(errm) - 1, 0, (struct sockaddr *)&from, flen); return 0; }
        uint16_t port_list[PROTECTED_PORTS_MAX]; unsigned port_n = 0;
        if (ports_csv && *ports_csv) { port_n = parse_ports_csv(ports_csv, port_list, PROTECTED_PORTS_MAX); }
        else if (cfg && cfg->num_ports > 0) { for (unsigned i = 0; i < cfg->num_ports && i < PROTECTED_PORTS_MAX; i++) port_list[port_n++] = ntohs(cfg->protected_ports[i]); }
        else if (map_ports_set >= 0) {
            __u16 k = 0, nx = 0; __u8 v = 0; int first = 1;
            while (port_n < PROTECTED_PORTS_MAX && bpf_map_get_next_key(map_ports_set, first ? NULL : &k, &nx) == 0) {
                first = 0; if (bpf_map_lookup_elem(map_ports_set, &nx, &v) == 0) port_list[port_n++] = ntohs(nx); k = nx;
            }
        }
        if (is_add) {
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            unsigned long long now_ns = (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
            struct allowed_entry val; memset(&val, 0, sizeof(val));
            unsigned long long idle_ns = have_idle ? (idle_sec < 0 ? (unsigned long long)(~0ULL) : (unsigned long long)idle_sec * 1000000000ull) : (cfg ? cfg->idle_extend_ns : 0);
            unsigned long long grace_ns = have_grace ? (grace_sec < 0 ? (unsigned long long)(~0ULL) : (unsigned long long)grace_sec * 1000000000ull) : (cfg ? cfg->post_disconnect_grace_ns : 0);
            val.allow_expires_at_ns = (idle_ns == (unsigned long long)(~0ULL)) ? (unsigned long long)(~0ULL) : now_ns + idle_ns;
            val.grace_expires_at_ns = (grace_ns == (unsigned long long)(~0ULL)) ? (unsigned long long)(~0ULL) : now_ns + grace_ns;
            val.initialized = 1;
            if (have_idle) val.idle_extend_ns_override = idle_ns;
            if (have_grace) val.grace_ns_override = grace_ns;
            struct in_addr a4; struct in6_addr a6; int is_v4 = 0, is_v6 = 0;
            if (ipbuf[0]) {
                is_v4 = inet_aton(ipbuf, &a4);
                if (!is_v4) is_v6 = (inet_pton(AF_INET6, ipbuf, &a6) == 1);
            }
            int added = 0;
            if (is_v4 && map_fd_v4 >= 0) {
                if (port_n > 0) {
                    for (unsigned i = 0; i < port_n; i++) { struct allowed_key k4; memset(&k4, 0, sizeof(k4)); k4.src = a4.s_addr; k4.dport = htons(port_list[i]); if (bpf_map_update_elem(map_fd_v4, &k4, &val, BPF_ANY) == 0) added++; }
                }
            } else if (is_v6 && map_fd_v6 >= 0) {
                if (port_n > 0) {
                    for (unsigned i = 0; i < port_n; i++) { struct allowed6_key k6; memset(&k6, 0, sizeof(k6)); memcpy(k6.src6, &a6, 16); k6.dport = htons(port_list[i]); if (bpf_map_update_elem(map_fd_v6, &k6, &val, BPF_ANY) == 0) added++; }
                }
            }
            char msg[512]; snprintf(msg, sizeof(msg), "Authorized %s for %d port(s) (idle=%llds grace=%llds)\n", ipbuf, added, idle_ns/1000000000ULL, grace_ns/1000000000ULL); (void)sendto(mgmt_fd, msg, strlen(msg), 0, (struct sockaddr *)&from, flen);
        } else if (is_del) {
            struct in_addr a4; struct in6_addr a6; int is_v4 = 0, is_v6 = 0;
            if (ipbuf[0]) {
                is_v4 = inet_aton(ipbuf, &a4);
                if (!is_v4) is_v6 = (inet_pton(AF_INET6, ipbuf, &a6) == 1);
            }
            int removed = 0;
            if (is_v4 && map_fd_v4 >= 0) {
                if (port_n > 0) {
                    for (unsigned i = 0; i < port_n; i++) { struct allowed_key k4; memset(&k4, 0, sizeof(k4)); k4.src = a4.s_addr; k4.dport = htons(port_list[i]); if (bpf_map_delete_elem(map_fd_v4, &k4) == 0) removed++; }
                } else {
                    struct allowed_key k4, nx4; int first = 1; memset(&k4, 0, sizeof(k4));
                    while (bpf_map_get_next_key(map_fd_v4, first ? NULL : &k4, &nx4) == 0) { first = 0; if (nx4.src == a4.s_addr) { if (bpf_map_delete_elem(map_fd_v4, &nx4) == 0) removed++; } k4 = nx4; }
                }
            } else if (is_v6 && map_fd_v6 >= 0) {
                if (port_n > 0) {
                    for (unsigned i = 0; i < port_n; i++) { struct allowed6_key k6; memset(&k6, 0, sizeof(k6)); memcpy(k6.src6, &a6, 16); k6.dport = htons(port_list[i]); if (bpf_map_delete_elem(map_fd_v6, &k6) == 0) removed++; }
                } else {
                    struct allowed6_key k6, nx6; int first = 1; memset(&k6, 0, sizeof(k6));
                    while (bpf_map_get_next_key(map_fd_v6, first ? NULL : &k6, &nx6) == 0) { first = 0; if (memcmp(nx6.src6, &a6, 16) == 0) { if (bpf_map_delete_elem(map_fd_v6, &nx6) == 0) removed++; } k6 = nx6; }
                }
            }
            char msg[256]; snprintf(msg, sizeof(msg), "Removed authorization for %s (%d entries)\n", ipbuf, removed); (void)sendto(mgmt_fd, msg, strlen(msg), 0, (struct sockaddr *)&from, flen);
        } else {
            static const char errm[] = "ERR invalid authorize cmd\nEND\n"; (void)sendto(mgmt_fd, errm, sizeof(errm) - 1, 0, (struct sockaddr *)&from, flen);
        }
        return 0;
    }
    return 0;
}


