// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>
#include <sys/types.h>

#include "spa_common.h"

// Handle a single management datagram on mgmt_fd. Non-blocking safe.
// Returns 0 on success or when no data; <0 on fatal error.
int mgmt_server_handle(int mgmt_fd,
                       const struct spa_config *cfg,
                       int map_fd_v4,
                       int map_fd_v6,
                       int map_always_v4,
                       int map_always_v6,
                       int map_ports_set,
                       int map_config,
                       int map_rl_v4,
                       int map_rl_v6);


