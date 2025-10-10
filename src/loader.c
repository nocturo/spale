// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>
#include <poll.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include "spa_common.h"
#include "spa_kern.skel.h"
#include "spa_kern_tc.skel.h"
#include "hpke.h"
#ifndef DEFAULT_CONF_PATH
#include "config_defaults.h"
#endif

static void trim(char *s)
{
    if (!s) return;
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n')) { s[n-1] = '\0'; n--; }
}

static void load_conf_kv_into_env(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        char *hash = strchr(val, '#');
        if (hash) { *hash = '\0'; }
        trim(key);
        trim(val);
        if (*key == '\0') continue;
        if (getenv(key) == NULL) {
            setenv(key, val, 0);
        }
    }
    fclose(f);
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

static bool port_in_cfg_list(uint16_t port_host, const struct spa_config *cfg)
{
    if (!cfg) return false;
    for (unsigned i = 0; i < cfg->num_ports; i++) {
        if (port_host == ntohs(cfg->protected_ports[i])) return true;
    }
    return false;
}

static int parse_int_env(const char *key, int defv)
{
    const char *v = getenv(key);
    if (!v || *v == '\0') return defv;
    return atoi(v);
}

static void parse_always_allow_any(int map_fd_v4, int lpm_fd_v4, int map_fd_v6, int lpm_fd_v6, const struct spa_config *cfg)
{
    const char *v = getenv("ALWAYS_ALLOW");
    if (!v || *v == '\0') return;
    const char *p = v;
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
            bool is_v4_host = false, is_v4_cidr = false;
            if (slash) {
                *slash = '\0';
                int prefix = atoi(slash + 1);
                if (prefix >= 0 && prefix <= 32 && inet_aton(ipbuf, &a4)) {
                    is_v4_cidr = true;
                    if (lpm_fd_v4 >= 0) {
                        struct lpm_v4 lk = { .prefixlen = (unsigned)prefix, .addr = a4.s_addr };
                        __u8 one = 1;
                        (void)bpf_map_update_elem(lpm_fd_v4, &lk, &one, BPF_ANY);
                    }
                }
                *slash = '/';
            } else if (inet_aton(ipbuf, &a4)) {
                is_v4_host = true;
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
                if (cfg && cfg->num_ports > 0) {
                    for (unsigned int i = 0; i < cfg->num_ports; i++) {
                        struct allowed_key k; memset(&k, 0, sizeof(k));
                        k.src = a4.s_addr; k.dport = cfg->protected_ports[i];
                        (void)bpf_map_update_elem(map_fd_v4, &k, &val, BPF_ANY);
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
                    if (cfg && cfg->num_ports > 0) {
                        for (unsigned int i = 0; i < cfg->num_ports; i++) {
                            struct allowed6_key k; memset(&k, 0, sizeof(k));
                            memcpy(k.src6, &a6, 16);
                            k.dport = cfg->protected_ports[i];
                            (void)bpf_map_update_elem(map_fd_v6, &k, &val, BPF_ANY);
                        }
                    }
                }
            }
        }
    }
}

typedef struct {
	uint8_t client_pub[32];
	uint32_t client_pub_len;
	uint32_t time_step;
	uint8_t nonce[16];
	uint32_t nonce_len;
	uint64_t added_ts;
} ReplayEntry;

#define REPLAY_CAP 4096
static ReplayEntry replay_cache[REPLAY_CAP];
static uint32_t replay_size = 0;
static uint32_t replay_rr_idx = 0;

static bool replay_seen_and_mark(const HpkePayload *pl)
{
	uint64_t now_ns = (uint64_t)time(NULL) * 1000000000ull;
	for (uint32_t i = 0; i < replay_size; i++) {
		ReplayEntry *e = &replay_cache[i];
		if (e->client_pub_len == pl->client_pub_len &&
			memcmp(e->client_pub, pl->client_pub, pl->client_pub_len) == 0 &&
			e->time_step == pl->time_step &&
			e->nonce_len == pl->nonce_len &&
			memcmp(e->nonce, pl->nonce, pl->nonce_len) == 0) {
			return true; // replay
		}
	}
    // insert or replace using round-robin when full
    uint32_t idx;
    if (replay_size < REPLAY_CAP) {
        idx = replay_size++;
    } else {
        idx = replay_rr_idx;
        replay_rr_idx = (replay_rr_idx + 1) % REPLAY_CAP;
    }
	ReplayEntry *e = &replay_cache[idx];
	e->client_pub_len = pl->client_pub_len;
	memcpy(e->client_pub, pl->client_pub, pl->client_pub_len);
	e->time_step = pl->time_step;
	e->nonce_len = pl->nonce_len;
	memcpy(e->nonce, pl->nonce, pl->nonce_len);
	e->added_ts = now_ns;
	return false;
}

static volatile sig_atomic_t keep_running = 1;
static void on_sigint(int signo) { (void)signo; keep_running = 0; }

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-c /etc/spale/spale.conf] -i <iface> -S <listen_port> [-t idle_sec] [-g grace_sec] [-m xdp|tc] [-p] [-n] --server-key <path> --clients <path> [--drop-privs user[:group]]\n", prog);
}
static int parse_user_group(const char *arg, uid_t *out_uid, gid_t *out_gid)
{
    if (!arg || !*arg || !out_uid || !out_gid) return -1;
    const char *colon = strchr(arg, ':');
    char u[128] = {0}, g[128] = {0};
    if (colon) {
        size_t ul = (size_t)(colon - arg);
        if (ul >= sizeof(u)) return -1;
        memcpy(u, arg, ul); u[ul] = '\0';
        strncpy(g, colon + 1, sizeof(g) - 1);
    } else {
        strncpy(u, arg, sizeof(u) - 1);
    }
    #ifndef NO_NSS
    struct passwd *pw = NULL;
    struct group *gr = NULL;
    #endif
    if (u[0]) {
        char *endp = NULL; long v = strtol(u, &endp, 10);
        if (endp && *endp == '\0') {
            *out_uid = (uid_t)v;
        } else {
#ifndef NO_NSS
            pw = getpwnam(u);
            if (!pw) return -1;
            *out_uid = (uid_t)pw->pw_uid;
#else
            return -1; /* name resolution not available in static/no-NSS builds */
#endif
        }
    }
    if (g[0]) {
        char *endp = NULL; long v = strtol(g, &endp, 10);
        if (endp && *endp == '\0') {
            *out_gid = (gid_t)v;
        } else {
#ifndef NO_NSS
            gr = getgrnam(g);
            if (!gr) return -1;
            *out_gid = (gid_t)gr->gr_gid;
#else
            return -1;
#endif
        }
    } else {
        /* group not provided */
        #ifndef NO_NSS
        struct passwd *pw2 = getpwuid(*out_uid);
        if (pw2) *out_gid = (gid_t)pw2->pw_gid;
        else return -1;
        #else
        /* require explicit numeric group when name service is disabled */
        return -1;
        #endif
    }
    return (*out_uid == (uid_t)-1 || *out_gid == (gid_t)-1) ? -1 : 0;
}

static int chown_pin_dir(const char *pin_dir, uid_t uid, gid_t gid)
{
    if (!pin_dir) return -1;
    if (chown(pin_dir, uid, gid) != 0) return -1;
    if (chmod(pin_dir, 0755) != 0) return -1;
    return 0;
}

static int drop_privileges(uid_t uid, gid_t gid)
{
    if (uid == (uid_t)-1 || gid == (gid_t)-1) return -1;
    // Prevent regaining privs
    (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    // Clear supplementary groups
    (void)setgroups(0, NULL);
    if (setgid(gid) != 0) return -1;
    if (setuid(uid) != 0) return -1;
    return 0;
}


static void build_hpke_aad(uint8_t aad[16])
{
    memset(aad, 0, 16);
    aad[6] = 1;
}

static bool hpke_try_decrypt(HpkeContext *hpke_ctx,
                             const uint8_t *cipher,
                             size_t cipher_len,
                             HpkePayload *out_pl)
{
    uint8_t aad[16];
    build_hpke_aad(aad);
    return hpke_verify_and_decrypt(hpke_ctx, aad, 7, cipher, cipher_len, out_pl);
}

static void apply_client_env_overrides(const HpkePayload *pl, struct allowed_entry *val)
{
    if (!pl || pl->client_id_len == 0) return;
    char envk[128];
    char cid_upper[80];
    size_t cu_len = pl->client_id_len < sizeof(cid_upper) - 1 ? pl->client_id_len : sizeof(cid_upper) - 1;
    for (size_t i = 0; i < cu_len; i++) {
        char c = (char)pl->client_id[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        cid_upper[i] = c;
    }
    cid_upper[cu_len] = '\0';

    snprintf(envk, sizeof(envk), "%s_IDLE_SEC", cid_upper);
    const char *v = getenv(envk);
    if (v && *v) {
        long s = strtol(v, NULL, 10);
        val->idle_extend_ns_override = (s < 0) ? (unsigned long long)(~0ULL) : (unsigned long long)s * 1000000000ull;
    }
    snprintf(envk, sizeof(envk), "%s_GRACE_SEC", cid_upper);
    v = getenv(envk);
    if (v && *v) {
        long s = strtol(v, NULL, 10);
        val->grace_ns_override = (s < 0) ? (unsigned long long)(~0ULL) : (unsigned long long)s * 1000000000ull;
    }
}

static unsigned load_client_ports_from_env_and_filter(const HpkePayload *pl,
                                                      const struct spa_config *cfg,
                                                      uint16_t *out_ports,
                                                      unsigned max_out)
{
    if (!pl || pl->client_id_len == 0) return 0;
    char envk[128];
    char cid_upper[80];
    size_t cu_len = pl->client_id_len < sizeof(cid_upper) - 1 ? pl->client_id_len : sizeof(cid_upper) - 1;
    for (size_t i = 0; i < cu_len; i++) {
        char c = (char)pl->client_id[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        cid_upper[i] = c;
    }
    cid_upper[cu_len] = '\0';

    snprintf(envk, sizeof(envk), "%s_PORTS", cid_upper);
    const char *v = getenv(envk);
    if (!v || !*v) return 0;

    unsigned client_n = parse_ports_csv(v, out_ports, max_out);
    for (unsigned i = 0; i < client_n;) {
        if (!port_in_cfg_list(out_ports[i], cfg)) {
            for (unsigned j = i + 1; j < client_n; j++) out_ports[j - 1] = out_ports[j];
            client_n--;
        } else {
            i++;
        }
    }
    return client_n;
}

static unsigned authorize_ipv4(int map_fd,
                               __u32 src_ip,
                               const struct spa_config *cfg,
                               const uint16_t *client_ports,
                               unsigned client_n,
                               const struct allowed_entry *val)
{
    unsigned wrote = 0;
    if (client_n > 0) {
        for (unsigned i = 0; i < client_n; i++) {
            struct allowed_key ak; memset(&ak, 0, sizeof(ak));
            ak.src = src_ip; ak.dport = htons(client_ports[i]);
            if (bpf_map_update_elem(map_fd, &ak, val, BPF_ANY) == 0) wrote++;
        }
    } else if (cfg->num_ports > 0) {
        for (unsigned i = 0; i < cfg->num_ports; i++) {
            struct allowed_key ak; memset(&ak, 0, sizeof(ak));
            ak.src = src_ip; ak.dport = cfg->protected_ports[i];
            if (bpf_map_update_elem(map_fd, &ak, val, BPF_ANY) == 0) wrote++;
        }
    }
    return wrote;
}

static unsigned authorize_ipv6(int map_fd,
                               const struct in6_addr *src6,
                               const struct spa_config *cfg,
                               const uint16_t *client_ports,
                               unsigned client_n,
                               const struct allowed_entry *val)
{
    unsigned wrote = 0;
    if (client_n > 0) {
        for (unsigned i = 0; i < client_n; i++) {
            struct allowed6_key ak; memset(&ak, 0, sizeof(ak));
            memcpy(ak.src6, src6, 16); ak.dport = htons(client_ports[i]);
            if (bpf_map_update_elem(map_fd, &ak, val, BPF_ANY) == 0) wrote++;
        }
    } else if (cfg->num_ports > 0) {
        for (unsigned i = 0; i < cfg->num_ports; i++) {
            struct allowed6_key ak; memset(&ak, 0, sizeof(ak));
            memcpy(ak.src6, src6, 16); ak.dport = cfg->protected_ports[i];
            if (bpf_map_update_elem(map_fd, &ak, val, BPF_ANY) == 0) wrote++;
        }
    }
    return wrote;
}

static int setup_udp4(uint16_t port, int *out_fd)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) { int e = errno; close(s); errno = e; return -1; }
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) (void)fcntl(s, F_SETFL, flags | O_NONBLOCK);
    *out_fd = s;
    return 0;
}

static int setup_udp6(uint16_t port, int *out_fd)
{
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int v6only = 1;
    (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    struct sockaddr_in6 addr6; memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons(port);
    if (bind(s, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) { int e = errno; close(s); errno = e; return -1; }
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) (void)fcntl(s, F_SETFL, flags | O_NONBLOCK);
    *out_fd = s;
    return 0;
}

struct loop_ctx {
    HpkeContext *hpke_ctx;
    const struct spa_config *cfg;
    int map_fd_v4;
    int map_fd_v6;
    int s4;
    int s6;
};

static void process_spa_v4(const struct loop_ctx *ctx)
{
    char buf[256];
    struct sockaddr_in peer; socklen_t plen = sizeof(peer);
    ssize_t n = recvfrom(ctx->s4, buf, sizeof(buf) - 1, MSG_DONTWAIT, (struct sockaddr *)&peer, &plen);
    if (n < 0) return;
    buf[n] = '\0';
    fprintf(stderr, "SPA from %s: %zd bytes\n", inet_ntoa(peer.sin_addr), n);

    HpkePayload pl;
    bool ok = hpke_try_decrypt(ctx->hpke_ctx, (const uint8_t *)buf, (size_t)n, &pl);
    if (ok && replay_seen_and_mark(&pl)) ok = false;
    if (!ok) return;

    __u32 src_ip = peer.sin_addr.s_addr;
    struct allowed_entry val; memset(&val, 0, sizeof(val));
    struct timespec ts_now_v4; clock_gettime(CLOCK_MONOTONIC, &ts_now_v4);
    uint64_t now_ns = (uint64_t)ts_now_v4.tv_sec * 1000000000ull + (uint64_t)ts_now_v4.tv_nsec;
    val.allow_expires_at_ns = now_ns + ctx->cfg->idle_extend_ns;
    val.grace_expires_at_ns = now_ns + ctx->cfg->post_disconnect_grace_ns;
    val.initialized = 1;
    apply_client_env_overrides(&pl, &val);

    uint16_t client_ports[PROTECTED_PORTS_MAX];
    unsigned client_n = load_client_ports_from_env_and_filter(&pl, ctx->cfg, client_ports, PROTECTED_PORTS_MAX);
    unsigned wrote = authorize_ipv4(ctx->map_fd_v4, src_ip, ctx->cfg, client_ports, client_n, &val);
    printf("Authorized %s for %u port(s)\n", inet_ntoa(peer.sin_addr), wrote);
}

static void process_spa_v6(const struct loop_ctx *ctx)
{
    char buf[256];
    struct sockaddr_in6 peer6; socklen_t plen6 = sizeof(peer6);
    ssize_t n2 = recvfrom(ctx->s6, buf, sizeof(buf) - 1, MSG_DONTWAIT, (struct sockaddr *)&peer6, &plen6);
    if (n2 < 0) return;
    buf[n2] = '\0';
    char abuf[INET6_ADDRSTRLEN];
    const char *astr = inet_ntop(AF_INET6, &peer6.sin6_addr, abuf, sizeof(abuf));
    if (!astr) astr = "<ipv6>";
    fprintf(stderr, "SPA from [%s]: %zd bytes\n", astr, n2);

    HpkePayload pl2;
    bool ok2 = hpke_try_decrypt(ctx->hpke_ctx, (const uint8_t *)buf, (size_t)n2, &pl2);
    if (ok2 && replay_seen_and_mark(&pl2)) ok2 = false;
    if (!ok2) return;

    struct allowed_entry val; memset(&val, 0, sizeof(val));
    struct timespec ts_now_v6; clock_gettime(CLOCK_MONOTONIC, &ts_now_v6);
    uint64_t now_ns = (uint64_t)ts_now_v6.tv_sec * 1000000000ull + (uint64_t)ts_now_v6.tv_nsec;
    val.allow_expires_at_ns = now_ns + ctx->cfg->idle_extend_ns;
    val.grace_expires_at_ns = now_ns + ctx->cfg->post_disconnect_grace_ns;
    val.initialized = 1;
    apply_client_env_overrides(&pl2, &val);

    uint16_t client_ports[PROTECTED_PORTS_MAX];
    unsigned client_n = load_client_ports_from_env_and_filter(&pl2, ctx->cfg, client_ports, PROTECTED_PORTS_MAX);
    unsigned wrote = authorize_ipv6(ctx->map_fd_v6, &peer6.sin6_addr, ctx->cfg, client_ports, client_n, &val);
    printf("Authorized [%s] for %u port(s)\n", astr, wrote);
}

static void run_poll_loop(const struct loop_ctx *ctx)
{
    struct pollfd pfds[2] = { { .fd = ctx->s4, .events = POLLIN }, { .fd = ctx->s6, .events = POLLIN } };
    while (keep_running) {
        int pr = poll(pfds, 2, 500);
        if (!keep_running) break;
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (pr == 0) continue;
        if (pfds[0].revents & POLLIN) process_spa_v4(ctx);
        if (pfds[1].revents & POLLIN) process_spa_v6(ctx);
    }
}

int main(int argc, char **argv) {
	const char *iface = NULL;
	uint16_t spa_port = 0;
    const char *server_key_path = NULL;
    const char *clients_path = NULL;
    const char *conf_path = DEFAULT_CONF_PATH;
    enum { MODE_XDP, MODE_TC } mode = MODE_TC;
    uint32_t idle_sec = 60;
	uint32_t grace_sec = 300;
    bool log_only = false;
    const char *drop_privs_arg = NULL;
    uid_t drop_uid = (uid_t)-1; gid_t drop_gid = (gid_t)-1;

    setvbuf(stdout, NULL, _IOLBF, 0);

bool pin_maps = false;
int opt;
while ((opt = getopt(argc, argv, "c:i:S:t:g:pm:n-:")) != -1) {
		switch (opt) {
        case 'c': conf_path = optarg; break;
		case 'i': iface = optarg; break;
		case 'S': spa_port = (uint16_t)atoi(optarg); break;
		case 't': idle_sec = (uint32_t)atoi(optarg); break;
		case 'g': grace_sec = (uint32_t)atoi(optarg); break;
	case 'p': pin_maps = true; break;
    case 'n': log_only = true; break;
    case 'm':
        if (strcmp(optarg, "xdp") == 0) mode = MODE_XDP;
        else if (strcmp(optarg, "tc") == 0) mode = MODE_TC;
        else { usage(argv[0]); return 1; }
        break;
    case '-':
        if (strcmp(optarg, "server-key") == 0 && optind < argc) { server_key_path = argv[optind++]; break; }
        if (strcmp(optarg, "clients") == 0 && optind < argc) { clients_path = argv[optind++]; break; }
        if (strcmp(optarg, "drop-privs") == 0 && optind < argc) { drop_privs_arg = argv[optind++]; break; }
        usage(argv[0]); return 1;
		default: usage(argv[0]); return 1;
		}
	}
    load_conf_kv_into_env(conf_path);

    if (!iface) iface = getenv("IFACE");
    if (spa_port == 0) { const char *sp = getenv("LISTEN_PORT"); if (sp) spa_port = (uint16_t)atoi(sp); }
    if (!server_key_path) server_key_path = getenv("SERVER_KEY");
    if (!clients_path) clients_path = getenv("CLIENTS_DIR");
    if (!server_key_path) server_key_path = DEFAULT_SERVER_KEY;
    if (!clients_path) clients_path = DEFAULT_CLIENTS_DIR;
    {
        const char *m = getenv("MODE");
        if (m) { if (strcmp(m, "xdp") == 0) mode = MODE_XDP; else if (strcmp(m, "tc") == 0) mode = MODE_TC; }
    }
    if (idle_sec == 60) idle_sec = (uint32_t)parse_int_env("IDLE_SEC", idle_sec);
    if (grace_sec == 300) grace_sec = (uint32_t)parse_int_env("GRACE_SEC", grace_sec);
    if (!log_only) log_only = parse_int_env("LOG_ONLY", 0) != 0;

    const char *pp_env = getenv("PROTECTED_PORTS");
    if (!iface || spa_port == 0 || !pp_env || *pp_env == '\0') {
        usage(argv[0]);
        return 1;
    }

    HpkeContext *hpke_ctx = NULL;
    if (!server_key_path || !clients_path) {
        fprintf(stderr, "require --server-key and --clients (directory of PEMs)\n");
        return 1;
    }
    char errbuf[256] = {0};
    hpke_ctx = hpke_init(server_key_path, clients_path, errbuf, sizeof(errbuf));
    if (!hpke_ctx) {
        fprintf(stderr, "HPKE init failed: %s\n", errbuf[0]?errbuf:"unknown");
        return 1;
    }
    fprintf(stderr, "HPKE auth enabled (server-key=%s, clients=%s)\n", server_key_path, clients_path);

	int ifindex = if_nametoindex(iface);
	if (ifindex == 0) { perror("if_nametoindex"); return 1; }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct spa_kern_bpf *xdp_skel = NULL;
    struct spa_kern_tc_bpf *tc_skel = NULL;
    if (mode == MODE_XDP) {
        xdp_skel = spa_kern_bpf__open();
        if (!xdp_skel) { fprintf(stderr, "Failed to open XDP BPF skeleton\n"); return 1; }
        if (spa_kern_bpf__load(xdp_skel)) { fprintf(stderr, "Failed to load XDP BPF\n"); return 1; }
    } else {
        tc_skel = spa_kern_tc_bpf__open();
        if (!tc_skel) { fprintf(stderr, "Failed to open TC BPF skeleton\n"); return 1; }
        if (spa_kern_tc_bpf__load(tc_skel)) { fprintf(stderr, "Failed to load TC BPF\n"); return 1; }
    }

    const char *pin_dir = "/sys/fs/bpf/spale";
    const char *allowed_path = "/sys/fs/bpf/spale/allowed_ipv4";
    const char *allowed6_path = "/sys/fs/bpf/spale/allowed_ipv6";
    const char *config_path  = "/sys/fs/bpf/spale/config_map";
    const char *ppset_path   = "/sys/fs/bpf/spale/protected_ports_set";
    if (pin_maps) {
        (void)mkdir("/sys/fs/bpf", 0755);
        (void)mkdir(pin_dir, 0755);
        // Clean up any stale pins from previous runs
        (void)unlink(allowed_path);
        (void)unlink(allowed6_path);
        (void)unlink(config_path);
        if (mode == MODE_XDP ? bpf_map__pin(xdp_skel->maps.allowed_ipv4, allowed_path) : bpf_map__pin(tc_skel->maps.allowed_ipv4, allowed_path)) {
            fprintf(stderr, "Warning: could not pin allowed_ipv4 map: %s\n", strerror(errno));
        }
        if (mode == MODE_XDP ? bpf_map__pin(xdp_skel->maps.allowed_ipv6, allowed6_path) : bpf_map__pin(tc_skel->maps.allowed_ipv6, allowed6_path)) {
            fprintf(stderr, "Warning: could not pin allowed_ipv6 map: %s\n", strerror(errno));
        }
        if (mode == MODE_XDP ? bpf_map__pin(xdp_skel->maps.config_map, config_path) : bpf_map__pin(tc_skel->maps.config_map, config_path)) {
            fprintf(stderr, "Warning: could not pin config_map: %s\n", strerror(errno));
        }
        (void)unlink(ppset_path);
        if (mode == MODE_XDP ? bpf_map__pin(xdp_skel->maps.protected_ports_set, ppset_path) : bpf_map__pin(tc_skel->maps.protected_ports_set, ppset_path)) {
            fprintf(stderr, "Warning: could not pin protected_ports_set: %s\n", strerror(errno));
        }
    }

    if (drop_privs_arg) {
        if (parse_user_group(drop_privs_arg, &drop_uid, &drop_gid) != 0) {
            fprintf(stderr, "invalid --drop-privs argument: %s\n", drop_privs_arg);
            return 1;
        }
        if (pin_maps) {
            if (chown_pin_dir(pin_dir, drop_uid, drop_gid) != 0) {
                fprintf(stderr, "warning: failed to chown %s to %u:%u, unpin at exit may fail\n", pin_dir, (unsigned)drop_uid, (unsigned)drop_gid);
            }
        }
    }

    struct spa_config cfg = {0};
    cfg.spa_port = htons(spa_port);
    cfg.idle_extend_ns = (uint64_t)idle_sec * 1000000000ull;
    cfg.post_disconnect_grace_ns = (uint64_t)grace_sec * 1000000000ull;
    cfg.spa_rl_rate_per_sec = (unsigned)parse_int_env("SPA_RL_RATE", 3);
    cfg.spa_rl_burst = (unsigned)parse_int_env("SPA_RL_BURST", 3);
    cfg.log_only = log_only ? 1u : 0u;
    const char *pp = getenv("PROTECTED_PORTS");
    cfg.num_ports = 0;
    if (pp && *pp) {
        unsigned int count = 0;
        const char *p = pp;
        while (*p && count < PROTECTED_PORTS_MAX) {
            while (*p == ' ' || *p == '\t' || *p == ',') p++;
            if (!*p) break;
            unsigned v = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (unsigned)(*p - '0'); p++; }
            if (v > 0 && v <= 65535) {
                cfg.protected_ports[count++] = htons((uint16_t)v);
            }
            while (*p && *p != ',') p++;
        }
        cfg.num_ports = count;
    }

	__u32 idx0 = 0;
    if (bpf_map_update_elem(bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.config_map : tc_skel->maps.config_map), &idx0, &cfg, BPF_ANY) != 0) {
		fprintf(stderr, "Failed to set config: %s\n", strerror(errno));
		return 1;
	}

    {
        int set_fd = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.protected_ports_set : tc_skel->maps.protected_ports_set);
        __u8 one = 1;
        if (cfg.num_ports > 0) {
            for (unsigned i = 0; i < cfg.num_ports; i++) {
                __u16 key = cfg.protected_ports[i];
                (void)bpf_map_update_elem(set_fd, &key, &one, BPF_ANY);
            }
        }
    }

    parse_always_allow_any(
        bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.allowed_ipv4 : tc_skel->maps.allowed_ipv4),
        bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.always_allow_v4 : tc_skel->maps.always_allow_v4),
        bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.allowed_ipv6 : tc_skel->maps.allowed_ipv6),
        bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.always_allow_v6 : tc_skel->maps.always_allow_v6),
        &cfg);

    __u32 xdp_flags = 0;
    struct bpf_tc_hook tc_hook = {0};
    struct bpf_tc_opts tc_opts = {0};
    if (mode == MODE_XDP) {
        xdp_flags = XDP_FLAGS_SKB_MODE;
        if (bpf_xdp_attach(ifindex, bpf_program__fd(xdp_skel->progs.xdp_spa), xdp_flags, NULL) != 0) {
            xdp_flags = XDP_FLAGS_DRV_MODE;
            if (bpf_xdp_attach(ifindex, bpf_program__fd(xdp_skel->progs.xdp_spa), xdp_flags, NULL) != 0) {
                perror("bpf_xdp_attach");
                return 1;
            }
        }
        unsigned pro_count = cfg.num_ports;
        printf("Attached XDP(%s) to %s, protecting %u port(s), SPA on %u\n",
               (xdp_flags == XDP_FLAGS_DRV_MODE ? "drv" : "skb"), iface, pro_count, spa_port);
    } else {
        tc_hook.sz = sizeof(tc_hook);
        tc_hook.ifindex = ifindex;
        tc_hook.attach_point = BPF_TC_INGRESS;
        int herr = bpf_tc_hook_create(&tc_hook);
        if (herr && herr != -EEXIST) {
            fprintf(stderr, "Failed to create tc hook (ensure clsact qdisc is available): %s\n", strerror(-herr));
            return 1;
        }
        tc_opts.sz = sizeof(tc_opts);
        tc_opts.handle = 1;
        tc_opts.priority = 1;
        tc_opts.prog_fd = bpf_program__fd(tc_skel->progs.tc_spa);
        tc_opts.flags = BPF_TC_F_REPLACE;
        int aerr = bpf_tc_attach(&tc_hook, &tc_opts);
        if (aerr) {
            fprintf(stderr, "Failed to attach tc program: %s\n", strerror(-aerr));
            (void)bpf_tc_hook_destroy(&tc_hook);
            return 1;
        }
        unsigned pro_count = cfg.num_ports;
        printf("Attached TC ingress to %s, protecting %u port(s), SPA on %u\n", iface, pro_count, spa_port);
    }

    int s4 = -1, s6 = -1;
	if (setup_udp4(spa_port, &s4) != 0) { perror("bind v4"); return 1; }
	if (setup_udp6(spa_port, &s6) != 0) { perror("bind v6"); return 1; }
	printf("Listening for SPA on 0.0.0.0:%u and [::]:%u\n", (unsigned)spa_port, (unsigned)spa_port);
    
    bool is_child = false;
    pid_t child_pid = -1;
    bool skip_runtime = false;
    if (drop_privs_arg) {
        child_pid = fork();
        if (child_pid < 0) { perror("fork"); return 1; }
        if (child_pid > 0) {
            // Parent: close sockets and wait for child to finish before cleanup
            skip_runtime = true;
            close(s4);
            close(s6);
        } else {
            // Child: will drop privileges and run
            is_child = true;
        }
    }

    // Drop privileges in child process only (or in single process if no fork)
    if (drop_privs_arg && is_child) {
        if (drop_privileges(drop_uid, drop_gid) != 0) {
            fprintf(stderr, "failed to drop privileges to %u:%u\n", (unsigned)drop_uid, (unsigned)drop_gid);
            return 1;
        }
        fprintf(stderr, "dropped privileges to uid=%u gid=%u\n", (unsigned)getuid(), (unsigned)getgid());
    }

	struct loop_ctx lctx;
	lctx.hpke_ctx = hpke_ctx;
	lctx.cfg = &cfg;
	lctx.map_fd_v4 = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.allowed_ipv4 : tc_skel->maps.allowed_ipv4);
	lctx.map_fd_v6 = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.allowed_ipv6 : tc_skel->maps.allowed_ipv6);
	lctx.s4 = s4;
	lctx.s6 = s6;

    if (!skip_runtime) {
        run_poll_loop(&lctx);
    } else {
        int status = 0;
        (void)waitpid(child_pid, &status, 0);
    }

    if (!skip_runtime) { close(s4); close(s6); }
    // If we are the child, exit now; parent will do privileged cleanup
    if (is_child) {
        if (hpke_ctx) hpke_free(hpke_ctx);
        _exit(0);
    }
    if (mode == MODE_XDP) {
        if (bpf_xdp_detach(ifindex, xdp_flags, NULL) != 0) {
            (void)bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
            (void)bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        }
    } else {
        (void)bpf_tc_detach(&tc_hook, &tc_opts);
        (void)bpf_tc_hook_destroy(&tc_hook);
    }
    if (pin_maps) {
        if (mode == MODE_XDP) {
            (void)bpf_map__unpin(xdp_skel->maps.allowed_ipv4, allowed_path);
            (void)bpf_map__unpin(xdp_skel->maps.allowed_ipv6, allowed6_path);
            (void)bpf_map__unpin(xdp_skel->maps.config_map, config_path);
            (void)bpf_map__unpin(xdp_skel->maps.protected_ports_set, ppset_path);
        } else {
            (void)bpf_map__unpin(tc_skel->maps.allowed_ipv4, allowed_path);
            (void)bpf_map__unpin(tc_skel->maps.allowed_ipv6, allowed6_path);
            (void)bpf_map__unpin(tc_skel->maps.config_map, config_path);
            (void)bpf_map__unpin(tc_skel->maps.protected_ports_set, ppset_path);
        }
        (void)rmdir(pin_dir);
    }
    if (mode == MODE_XDP) spa_kern_bpf__destroy(xdp_skel);
    else spa_kern_tc_bpf__destroy(tc_skel);
    if (hpke_ctx) hpke_free(hpke_ctx);
	return 0;
}


