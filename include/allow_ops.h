// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>
#include <netinet/in.h>

#include "spa_common.h"

unsigned authorize_ipv4(int map_fd,
                        __u32 src_ip,
                        const struct spa_config *cfg,
                        const uint16_t *client_ports,
                        unsigned client_n,
                        const struct allowed_entry *val);

unsigned authorize_ipv6(int map_fd,
                        const struct in6_addr *src6,
                        const struct spa_config *cfg,
                        const uint16_t *client_ports,
                        unsigned client_n,
                        const struct allowed_entry *val);

unsigned authorize_addr(int af,
                        int map_fd_v4,
                        int map_fd_v6,
                        const void *src_addr,
                        const struct spa_config *cfg,
                        const uint16_t *client_ports,
                        unsigned client_n,
                        const struct allowed_entry *val);


