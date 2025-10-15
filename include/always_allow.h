// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "spa_common.h"

// Parse ALWAYS_ALLOW env var and populate allow and LPM maps.
// Returns number of entries added (best-effort), may be partial.
unsigned always_allow_parse_and_apply(const char *env_value,
                                      int map_fd_v4,
                                      int lpm_fd_v4,
                                      int map_fd_v6,
                                      int lpm_fd_v6,
                                      const struct spa_config *cfg);


