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
#include <getopt.h>
#include <sys/un.h>
#include <dirent.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include "spa_common.h"
#include "spa_kern.skel.h"
#include "spa_kern_tc.skel.h"
#include "hpke.h"
#include "mgmt_server.h"
#include "mgmt_client.h"
#include "always_allow.h"
#include "logger.h"
#include "paths.h"
#include "allow_ops.h"
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

#define REPLAY_HT_CAP 8192u
#define REPLAY_MAX_PROBE 32u
static uint64_t replay_table[REPLAY_HT_CAP];
static unsigned char replay_slot_used[REPLAY_HT_CAP];
static uint32_t replay_entries = 0;

static uint64_t replay_hash(const HpkePayload *pl)
{
    /* FNV-1a 64-bit over client_pub || time_step (BE) || nonce */
    const uint64_t FNV_OFF = 14695981039346656037ull;
    const uint64_t FNV_PRIME = 1099511628211ull;
    uint64_t h = FNV_OFF;
    for (uint32_t i = 0; i < pl->client_pub_len; i++) { h ^= pl->client_pub[i]; h *= FNV_PRIME; }
    uint8_t tsb[4]; tsb[0] = (uint8_t)((pl->time_step >> 24) & 0xFF); tsb[1] = (uint8_t)((pl->time_step >> 16) & 0xFF); tsb[2] = (uint8_t)((pl->time_step >> 8) & 0xFF); tsb[3] = (uint8_t)(pl->time_step & 0xFF);
    for (int i = 0; i < 4; i++) { h ^= tsb[i]; h *= FNV_PRIME; }
    for (uint32_t i = 0; i < pl->nonce_len; i++) { h ^= pl->nonce[i]; h *= FNV_PRIME; }
    return h;
}

static bool replay_seen_and_mark(const HpkePayload *pl)
{
    uint64_t tag = replay_hash(pl);
    uint32_t mask = REPLAY_HT_CAP - 1u;
    uint32_t idx = (uint32_t)tag & mask;
    for (uint32_t i = 0; i < REPLAY_MAX_PROBE; i++) {
        uint32_t p = (idx + i) & mask;
        if (replay_slot_used[p]) {
            if (replay_table[p] == tag) return true; /* replay */
    } else {
            replay_table[p] = tag;
            replay_slot_used[p] = 1;
            if (replay_entries < REPLAY_HT_CAP) replay_entries++;
            return false;
        }
    }
    /* table is dense around idx; overwrite base slot */
    replay_table[idx] = tag;
    replay_slot_used[idx] = 1;
    if (replay_entries < REPLAY_HT_CAP) replay_entries++;
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


#define HPKE_AAD_LEN 7
static void build_hpke_aad(uint8_t aad[HPKE_AAD_LEN])
{
    memset(aad, 0, HPKE_AAD_LEN);
    aad[6] = 1;
}

static size_t build_client_env_prefix(const HpkePayload *pl, char *cid_upper, size_t cid_upper_len)
{
    if (!pl || pl->client_id_len == 0 || !cid_upper || cid_upper_len == 0) return 0;
    size_t cu_len = pl->client_id_len < cid_upper_len - 1 ? pl->client_id_len : cid_upper_len - 1;
    for (size_t i = 0; i < cu_len; i++) {
        char c = (char)pl->client_id[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        cid_upper[i] = c;
    }
    cid_upper[cu_len] = '\0';
    return cu_len;
}

static bool hpke_try_decrypt(HpkeContext *hpke_ctx,
                             const uint8_t *cipher,
                             size_t cipher_len,
                             HpkePayload *out_pl)
{
    uint8_t aad[HPKE_AAD_LEN];
    build_hpke_aad(aad);
    bool ok = hpke_verify_and_decrypt(hpke_ctx, aad, HPKE_AAD_LEN, cipher, cipher_len, out_pl);
    if (!ok) LOG_WARN("HPKE decrypt failed (len=%zu)", cipher_len);
    return ok;
}

static void apply_client_env_overrides(const HpkePayload *pl, struct allowed_entry *val)
{
    if (!pl || pl->client_id_len == 0) return;
    char envk[128];
    char cid_upper[80];
    size_t cu_len = build_client_env_prefix(pl, cid_upper, sizeof(cid_upper));
    if (cu_len == 0) return;

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
    size_t cu_len = build_client_env_prefix(pl, cid_upper, sizeof(cid_upper));
    if (cu_len == 0) return 0;

    snprintf(envk, sizeof(envk), "%s_PORTS", cid_upper);
    const char *v = getenv(envk);
    if (!v || !*v) {
        LOG_WARN("No client ports env for key %s", envk);
        return 0;
    }

    unsigned client_n = parse_ports_csv(v, out_ports, max_out);
    LOG_INFO("Client %s requested %u port(s) via %s", cid_upper, client_n, envk);
    for (unsigned i = 0; i < client_n;) {
        if (!port_in_cfg_list(out_ports[i], cfg)) {
            for (unsigned j = i + 1; j < client_n; j++) out_ports[j - 1] = out_ports[j];
            client_n--;
        } else {
            i++;
        }
    }
    LOG_INFO("Client %s authorized %u port(s) after filter", cid_upper, client_n);
    return client_n;
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
    int map_always_v4;
    int map_always_v6;
    int map_ports_set;
    int map_config;
    int map_rl_v4;
    int map_rl_v6;
    int s4;
    int s6;
    int mgmt_fd;
};

static void process_spa_generic(const struct loop_ctx *ctx, int af, int sock_fd)
{
    char buf[256];
    ssize_t n = -1;
    if (af == AF_INET) {
    struct sockaddr_in peer; socklen_t plen = sizeof(peer);
        n = recvfrom(sock_fd, buf, sizeof(buf) - 1, MSG_DONTWAIT, (struct sockaddr *)&peer, &plen);
    if (n < 0) return;
    buf[n] = '\0';
    LOG_DEBUG("SPA from %s: %zd bytes", inet_ntoa(peer.sin_addr), n);

    HpkePayload pl;
    bool ok = hpke_try_decrypt(ctx->hpke_ctx, (const uint8_t *)buf, (size_t)n, &pl);
    if (ok && replay_seen_and_mark(&pl)) { LOG_WARN("HPKE replay detected"); ok = false; }
    if (!ok) return;

    struct allowed_entry val; memset(&val, 0, sizeof(val));
        struct timespec ts_now; clock_gettime(CLOCK_MONOTONIC, &ts_now);
        uint64_t now_ns = (uint64_t)ts_now.tv_sec * 1000000000ull + (uint64_t)ts_now.tv_nsec;
    val.allow_expires_at_ns = now_ns + ctx->cfg->idle_extend_ns;
    val.grace_expires_at_ns = now_ns + ctx->cfg->post_disconnect_grace_ns;
    val.initialized = 1;
    apply_client_env_overrides(&pl, &val);

    uint16_t client_ports[PROTECTED_PORTS_MAX];
    unsigned client_n = load_client_ports_from_env_and_filter(&pl, ctx->cfg, client_ports, PROTECTED_PORTS_MAX);
        unsigned wrote = authorize_addr(AF_INET, ctx->map_fd_v4, ctx->map_fd_v6, &peer.sin_addr.s_addr, ctx->cfg, client_ports, client_n, &val);
    LOG_INFO("Authorized %s for %u port(s)", inet_ntoa(peer.sin_addr), wrote);
    } else if (af == AF_INET6) {
    struct sockaddr_in6 peer6; socklen_t plen6 = sizeof(peer6);
        n = recvfrom(sock_fd, buf, sizeof(buf) - 1, MSG_DONTWAIT, (struct sockaddr *)&peer6, &plen6);
        if (n < 0) return;
        buf[n] = '\0';
    char abuf[INET6_ADDRSTRLEN];
    const char *astr = inet_ntop(AF_INET6, &peer6.sin6_addr, abuf, sizeof(abuf));
    if (!astr) astr = "<ipv6>";
        LOG_DEBUG("SPA from [%s]: %zd bytes", astr, n);

    HpkePayload pl2;
        bool ok2 = hpke_try_decrypt(ctx->hpke_ctx, (const uint8_t *)buf, (size_t)n, &pl2);
    if (ok2 && replay_seen_and_mark(&pl2)) { LOG_WARN("HPKE replay detected (v6)"); ok2 = false; }
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
        unsigned wrote = authorize_addr(AF_INET6, ctx->map_fd_v4, ctx->map_fd_v6, &peer6.sin6_addr, ctx->cfg, client_ports, client_n, &val);
    LOG_INFO("Authorized [%s] for %u port(s)", astr, wrote);
    }
}

static void process_spa_v4(const struct loop_ctx *ctx)
{
    process_spa_generic(ctx, AF_INET, ctx->s4);
}

static void process_spa_v6(const struct loop_ctx *ctx)
{
    process_spa_generic(ctx, AF_INET6, ctx->s6);
}

static void run_poll_loop(const struct loop_ctx *ctx)
{
    struct pollfd pfds[3];
    pfds[0].fd = ctx->s4; pfds[0].events = POLLIN;
    pfds[1].fd = ctx->s6; pfds[1].events = POLLIN;
    pfds[2].fd = ctx->mgmt_fd; pfds[2].events = POLLIN;
    while (keep_running) {
        int pr = poll(pfds, 3, 500);
        if (!keep_running) break;
        if (pr < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("poll failed: %s", strerror(errno));
            break;
        }
        if (pr == 0) continue;
        if (pfds[0].revents & POLLIN) process_spa_v4(ctx);
        if (pfds[1].revents & POLLIN) process_spa_v6(ctx);
        if (pfds[2].fd >= 0 && (pfds[2].revents & POLLIN)) {
            (void)mgmt_server_handle(pfds[2].fd, ctx->cfg,
                                     ctx->map_fd_v4, ctx->map_fd_v6,
                                     ctx->map_always_v4, ctx->map_always_v6,
                                     ctx->map_ports_set, ctx->map_config,
                                     ctx->map_rl_v4, ctx->map_rl_v6);
        }
    }
}

static int setup_mgmt_socket(const char **out_path)
{
    if (out_path) *out_path = NULL;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    const char *sock_path = SPALE_MGMT_SOCK;
    memset(addr.sun_path, 0, sizeof(addr.sun_path));
    (void)snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    (void)unlink(addr.sun_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { int e = errno; close(fd); errno = e; return -1; }
    // Restrict access to root only
    (void)chmod(sock_path, 0600);
    int flags = fcntl(fd, F_GETFL, 0); if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (out_path) *out_path = sock_path;
    return fd;
}

int main(int argc, char **argv) {
	const char *iface = NULL;
	uint16_t spa_port = 0;
    const char *server_key_path = NULL;
    const char *clients_path = NULL;
    const char *conf_path = SPALE_DEFAULT_CONF_PATH;
    enum { MODE_XDP, MODE_TC } mode = MODE_TC;
    uint32_t idle_sec = 60;
	uint32_t grace_sec = 300;
    bool log_only = false;
    bool manage_mode = false;
    const char *drop_privs_arg = NULL;
    uid_t drop_uid = (uid_t)-1; gid_t drop_gid = (gid_t)-1;

    setvbuf(stdout, NULL, _IOLBF, 0);

    // Check for manage mode first to avoid parsing manage-specific options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--manage") == 0) {
            manage_mode = true;
            if (i + 1 >= argc) { fprintf(stderr, "Usage: %s --manage <list|authorize|allowlist> ...\n", argv[0]); return 1; }
            return manage_main(argc - i - 1, argv + i + 1);
        }
    }

bool pin_maps = false;
static struct option long_opts[] = {
    {"server-key", required_argument, 0, 1000},
    {"clients", required_argument, 0, 1001},
    {"drop-privs", required_argument, 0, 1002},
    {"manage", no_argument, 0, 1003},
    {0, 0, 0, 0}
};
int opt, longidx = 0;
while ((opt = getopt_long(argc, argv, "c:i:S:t:g:pm:n", long_opts, &longidx)) != -1) {
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
        case 1000: server_key_path = optarg; break;
        case 1001: clients_path = optarg; break;
        case 1002: drop_privs_arg = optarg; break;
        case 1003: manage_mode = true; break;
		default: usage(argv[0]); return 1;
		}
	}
    if (manage_mode) {
        // Delegate to manage subcommand parser
        if (optind >= argc) { fprintf(stderr, "Usage: %s --manage <list|authorize|allowlist> ...\n", argv[0]); return 1; }
        return manage_main(argc - optind, argv + optind);
	}
    // Check for existing instance using PID file BEFORE any network changes
    const char *pidfile_path = SPALE_PID_FILE;
    
    FILE *pidfile = fopen(pidfile_path, "r");
    if (pidfile) {
        pid_t existing_pid = 0;
        if (fscanf(pidfile, "%d", &existing_pid) == 1) {
            // Check if the PID is still running
            if (kill(existing_pid, 0) == 0) {
                fprintf(stderr, "Another spale instance is already running (PID %d)\n", existing_pid);
                fclose(pidfile);
                return 1;
            }
        }
        fclose(pidfile);
        // Remove stale PID file
        unlink(pidfile_path);
    }

    load_conf_kv_into_env(conf_path);

    if (!iface) iface = getenv("IFACE");
    if (spa_port == 0) { const char *sp = getenv("LISTEN_PORT"); if (sp) spa_port = (uint16_t)atoi(sp); }
    if (!server_key_path) server_key_path = getenv("SERVER_KEY");
    if (!clients_path) clients_path = getenv("CLIENTS_DIR");
    if (!server_key_path) server_key_path = SPALE_DEFAULT_SERVER_KEY;
    if (!clients_path) clients_path = SPALE_DEFAULT_CLIENTS_DIR;
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
        LOG_ERROR("require --server-key and --clients (directory of PEMs)");
        return 1;
    }
    char errbuf[256] = {0};
    hpke_ctx = hpke_init(server_key_path, clients_path, errbuf, sizeof(errbuf));
    if (!hpke_ctx) {
        LOG_ERROR("HPKE init failed: %s", errbuf[0]?errbuf:"unknown");
        return 1;
    }
    LOG_INFO("HPKE auth enabled (server-key=%s, clients=%s)", server_key_path, clients_path);

	int ifindex = if_nametoindex(iface);
    if (ifindex == 0) { LOG_ERROR("if_nametoindex failed for %s", iface); return 1; }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct spa_kern_bpf *xdp_skel = NULL;
    struct spa_kern_tc_bpf *tc_skel = NULL;
    if (mode == MODE_XDP) {
        xdp_skel = spa_kern_bpf__open();
        if (!xdp_skel) { LOG_ERROR("Failed to open XDP BPF skeleton"); return 1; }
        if (spa_kern_bpf__load(xdp_skel)) { LOG_ERROR("Failed to load XDP BPF"); return 1; }
    } else {
        tc_skel = spa_kern_tc_bpf__open();
        if (!tc_skel) { LOG_ERROR("Failed to open TC BPF skeleton"); return 1; }
        if (spa_kern_tc_bpf__load(tc_skel)) { LOG_ERROR("Failed to load TC BPF"); return 1; }
    }

    const char *pin_dir = SPALE_PIN_DIR;
    const char *allowed_path = SPALE_PIN_ALLOWED_V4;
    const char *allowed6_path = SPALE_PIN_ALLOWED_V6;
    const char *config_path  = SPALE_PIN_CONFIG_MAP;
    const char *ppset_path   = SPALE_PIN_PROTECTED_PORTS;
    if (pin_maps) {
        (void)mkdir("/sys/fs/bpf", 0755);
        (void)mkdir(pin_dir, 0755);
        // Clean up any stale pins from previous runs
        (void)unlink(allowed_path);
        (void)unlink(allowed6_path);
        (void)unlink(config_path);
        if (mode == MODE_XDP ? bpf_map__pin(xdp_skel->maps.allowed_ipv4, allowed_path) : bpf_map__pin(tc_skel->maps.allowed_ipv4, allowed_path)) {
            LOG_WARN("could not pin allowed_ipv4 map: %s", strerror(errno));
        }
        if (mode == MODE_XDP ? bpf_map__pin(xdp_skel->maps.allowed_ipv6, allowed6_path) : bpf_map__pin(tc_skel->maps.allowed_ipv6, allowed6_path)) {
            LOG_WARN("could not pin allowed_ipv6 map: %s", strerror(errno));
        }
        if (mode == MODE_XDP ? bpf_map__pin(xdp_skel->maps.config_map, config_path) : bpf_map__pin(tc_skel->maps.config_map, config_path)) {
            LOG_WARN("could not pin config_map: %s", strerror(errno));
        }
        (void)unlink(ppset_path);
        if (mode == MODE_XDP ? bpf_map__pin(xdp_skel->maps.protected_ports_set, ppset_path) : bpf_map__pin(tc_skel->maps.protected_ports_set, ppset_path)) {
            LOG_WARN("could not pin protected_ports_set: %s", strerror(errno));
        }
    }

    if (drop_privs_arg) {
        if (parse_user_group(drop_privs_arg, &drop_uid, &drop_gid) != 0) {
            LOG_ERROR("invalid --drop-privs argument: %s", drop_privs_arg);
            return 1;
        }
        if (pin_maps) {
            if (chown_pin_dir(pin_dir, drop_uid, drop_gid) != 0) {
                LOG_WARN("failed to chown %s to %u:%u, unpin at exit may fail", pin_dir, (unsigned)drop_uid, (unsigned)drop_gid);
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
		LOG_ERROR("Failed to set config: %s", strerror(errno));
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

    always_allow_parse_and_apply(
        getenv("ALWAYS_ALLOW"),
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
                LOG_ERROR("bpf_xdp_attach failed (drv+skb)");
                return 1;
            }
        }
        unsigned pro_count = cfg.num_ports;
        LOG_INFO("Attached XDP(%s) to %s, protecting %u port(s), SPA on %u",
               (xdp_flags == XDP_FLAGS_DRV_MODE ? "drv" : "skb"), iface, pro_count, spa_port);
    } else {
        tc_hook.sz = sizeof(tc_hook);
        tc_hook.ifindex = ifindex;
        tc_hook.attach_point = BPF_TC_INGRESS;
        int herr = bpf_tc_hook_create(&tc_hook);
        if (herr && herr != -EEXIST) {
            LOG_ERROR("Failed to create tc hook (ensure clsact qdisc is available): %s", strerror(-herr));
            return 1;
        }
        tc_opts.sz = sizeof(tc_opts);
        tc_opts.handle = 1;
        tc_opts.priority = 1;
        tc_opts.prog_fd = bpf_program__fd(tc_skel->progs.tc_spa);
        tc_opts.flags = BPF_TC_F_REPLACE;
        int aerr = bpf_tc_attach(&tc_hook, &tc_opts);
        if (aerr) {
            LOG_ERROR("Failed to attach tc program: %s", strerror(-aerr));
            (void)bpf_tc_hook_destroy(&tc_hook);
            return 1;
        }
        unsigned pro_count = cfg.num_ports;
        LOG_INFO("Attached TC ingress to %s, protecting %u port(s), SPA on %u", iface, pro_count, spa_port);
    }

    int s4 = -1, s6 = -1;
    if (setup_udp4(spa_port, &s4) != 0) { LOG_ERROR("bind v4 failed on %u", (unsigned)spa_port); return 1; }
    if (setup_udp6(spa_port, &s6) != 0) { LOG_ERROR("bind v6 failed on %u", (unsigned)spa_port); return 1; }
    LOG_INFO("Listening for SPA on 0.0.0.0:%u and [::]:%u", (unsigned)spa_port, (unsigned)spa_port);
    
    // Only create PID file after successful port binding
    pidfile = fopen(pidfile_path, "w");
    if (pidfile) {
        fprintf(pidfile, "%d\n", getpid());
        fclose(pidfile);
    }
    
    // Create management socket as root; pass FD to child after fork
    const char *mgmt_sock_path = NULL;
    int mgmt_fd = setup_mgmt_socket(&mgmt_sock_path);
    if (mgmt_fd < 0) {
        LOG_ERROR("Another spale instance appears to be running (management socket busy)");
        return 1;
    }
    LOG_INFO("management socket: %s", mgmt_sock_path);
    
    bool is_child = false;
    pid_t child_pid = -1;
    bool skip_runtime = false;
    if (drop_privs_arg) {
        child_pid = fork();
        if (child_pid < 0) { LOG_ERROR("fork failed: %s", strerror(errno)); return 1; }
        if (child_pid > 0) {
            // Parent: close sockets and wait for child to finish before cleanup
            skip_runtime = true;
            close(s4);
            close(s6);
            if (mgmt_fd >= 0) { close(mgmt_fd); }
        } else {
            // Child: will drop privileges and run
            is_child = true;
        }
    }

    // Drop privileges in child process only (or in single process if no fork)
    if (drop_privs_arg && is_child) {
        if (drop_privileges(drop_uid, drop_gid) != 0) {
            LOG_ERROR("failed to drop privileges to %u:%u", (unsigned)drop_uid, (unsigned)drop_gid);
            return 1;
        }
        LOG_INFO("dropped privileges to uid=%u gid=%u", (unsigned)getuid(), (unsigned)getgid());
    }

	struct loop_ctx lctx;
	lctx.hpke_ctx = hpke_ctx;
	lctx.cfg = &cfg;
	lctx.map_fd_v4 = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.allowed_ipv4 : tc_skel->maps.allowed_ipv4);
	lctx.map_fd_v6 = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.allowed_ipv6 : tc_skel->maps.allowed_ipv6);
    lctx.map_always_v4 = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.always_allow_v4 : tc_skel->maps.always_allow_v4);
    lctx.map_always_v6 = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.always_allow_v6 : tc_skel->maps.always_allow_v6);
    lctx.map_ports_set = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.protected_ports_set : tc_skel->maps.protected_ports_set);
    lctx.map_config = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.config_map : tc_skel->maps.config_map);
    lctx.map_rl_v4 = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.spa_rl : tc_skel->maps.spa_rl);
    lctx.map_rl_v6 = bpf_map__fd(mode == MODE_XDP ? xdp_skel->maps.spa_rl6 : tc_skel->maps.spa_rl6);
	lctx.s4 = s4;
	lctx.s6 = s6;
    lctx.mgmt_fd = mgmt_fd;

    if (!skip_runtime) {
        run_poll_loop(&lctx);
    } else {
        int status = 0;
        (void)waitpid(child_pid, &status, 0);
    }

    if (!skip_runtime) { close(s4); close(s6); }
    if (mgmt_fd >= 0) { if (mgmt_sock_path) (void)unlink(mgmt_sock_path); close(mgmt_fd); }
    
    // Clean up PID file
    unlink(pidfile_path);
    
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


