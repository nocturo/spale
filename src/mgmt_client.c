// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <stddef.h>

#include "mgmt_client.h"
#include "paths.h"

static int manage_cmd_list(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (argc >= 1 && strcmp(argv[0], "authorized") == 0) {
        return mgmt_client_request("list authorized");
    } else if (argc >= 1 && strcmp(argv[0], "allowlist") == 0) {
        return mgmt_client_request("list allowlist");
    } else if (argc >= 1 && strcmp(argv[0], "ports") == 0) {
        return mgmt_client_request("list ports");
    } else if (argc >= 1 && (strcmp(argv[0], "ratelimit") == 0 || strcmp(argv[0], "rl") == 0)) {
        return mgmt_client_request("list ratelimit");
    }
    fprintf(stderr, "manage list <authorized|allowlist|ports|ratelimit>\n");
    return 1;
}

static int manage_cmd_authorize(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "manage authorize <add|del> --ip <ADDR> [--ports csv] [--idle-sec N|-1] [--grace-sec N|-1]\n"); return 1; }
    const char *op = argv[0];
    const char *ip = NULL; const char *ports_csv = NULL; long idle_sec = 0; long grace_sec = 0; int have_idle = 0, have_grace = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) { ip = argv[++i]; continue; }
        if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) { ports_csv = argv[++i]; continue; }
        if (strcmp(argv[i], "--idle-sec") == 0 && i + 1 < argc) { idle_sec = strtol(argv[++i], NULL, 10); have_idle = 1; continue; }
        if (strcmp(argv[i], "--grace-sec") == 0 && i + 1 < argc) { grace_sec = strtol(argv[++i], NULL, 10); have_grace = 1; continue; }
    }
    if (!ip) { fprintf(stderr, "--ip required\n"); return 1; }

    char req[512]; size_t off = 0;
    if (strcmp(op, "add") == 0) {
        off += snprintf(req + off, sizeof(req) - off, "authorize add --ip %s", ip);
        if (ports_csv && *ports_csv) off += snprintf(req + off, sizeof(req) - off, " --ports %s", ports_csv);
        if (have_idle) off += snprintf(req + off, sizeof(req) - off, " --idle-sec %ld", idle_sec);
        if (have_grace) off += snprintf(req + off, sizeof(req) - off, " --grace-sec %ld", grace_sec);
        off += snprintf(req + off, sizeof(req) - off, "\n");
    } else if (strcmp(op, "del") == 0 || strcmp(op, "rm") == 0) {
        off += snprintf(req + off, sizeof(req) - off, "authorize del --ip %s", ip);
        if (ports_csv && *ports_csv) off += snprintf(req + off, sizeof(req) - off, " --ports %s", ports_csv);
        off += snprintf(req + off, sizeof(req) - off, "\n");
    } else {
        fprintf(stderr, "manage authorize <add|del> ...\n"); return 1;
    }
    return mgmt_client_request(req);
}

static int manage_cmd_allowlist(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "manage allowlist <add|del> <CIDR|IP>\n"); return 1; }
    const char *op = argv[0]; const char *arg = argv[1];
    char req[256];
    if (strcmp(op, "add") == 0) {
        snprintf(req, sizeof(req), "allowlist add %s\n", arg);
    } else if (strcmp(op, "del") == 0 || strcmp(op, "rm") == 0) {
        snprintf(req, sizeof(req), "allowlist del %s\n", arg);
    } else {
        fprintf(stderr, "manage allowlist <add|del> <CIDR|IP>\n"); return 1;
    }
    return mgmt_client_request(req);
}

int manage_main(int argc, char **argv)
{
    if (argc < 1) { fprintf(stderr, "manage <list|authorize|allowlist> ...\n"); return 1; }
    if (strcmp(argv[0], "list") == 0) return manage_cmd_list(argc - 1, argv + 1);
    if (strcmp(argv[0], "authorize") == 0) return manage_cmd_authorize(argc - 1, argv + 1);
    if (strcmp(argv[0], "allowlist") == 0) return manage_cmd_allowlist(argc - 1, argv + 1);
    fprintf(stderr, "manage <list|authorize|allowlist> ...\n");
    return 1;
}

int mgmt_client_request(const char *req)
{
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int ok = -1;
    struct sockaddr_un caddr; memset(&caddr, 0, sizeof(caddr));
    caddr.sun_family = AF_UNIX;
    caddr.sun_path[0] = '\0';
    (void)snprintf(caddr.sun_path + 1, sizeof(caddr.sun_path) - 1, "spale.mgmt.%d.%lu", (int)getpid(), (unsigned long)time(NULL));
    socklen_t clen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(caddr.sun_path + 1));
    if (bind(s, (struct sockaddr *)&caddr, clen) != 0) { int e = errno; close(s); errno = e; return -1; }
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr)); addr.sun_family = AF_UNIX;
    (void)snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SPALE_MGMT_SOCK);
    struct timeval tv; tv.tv_sec = 2; tv.tv_usec = 0; (void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (sendto(s, req, strlen(req), 0, (struct sockaddr *)&addr, sizeof(addr)) >= 0) {
        for (;;) {
            char buf[512]; ssize_t n = recvfrom(s, buf, sizeof(buf) - 1, 0, NULL, NULL);
            if (n < 0) { ok = 0; break; }
            buf[n] = '\0';
            if (strcmp(buf, "END\n") == 0) { ok = 1; break; }
            fputs(buf, stdout);
        }
    }
    close(s);
    return ok == 1 ? 0 : -1;
}


