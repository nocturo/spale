// SPDX-License-Identifier: MIT
#pragma once

// Centralized default filesystem paths

#define SPALE_PIN_DIR                "/sys/fs/bpf/spale"
#define SPALE_PIN_ALLOWED_V4         SPALE_PIN_DIR "/allowed_ipv4"
#define SPALE_PIN_ALLOWED_V6         SPALE_PIN_DIR "/allowed_ipv6"
#define SPALE_PIN_CONFIG_MAP         SPALE_PIN_DIR "/config_map"
#define SPALE_PIN_PROTECTED_PORTS    SPALE_PIN_DIR "/protected_ports_set"

#define SPALE_MGMT_SOCK              "/run/spale.sock"
#define SPALE_PID_FILE               "/run/spale.pid"

#define SPALE_STR_HELPER(x) #x
#define SPALE_STR(x) SPALE_STR_HELPER(x)

#ifndef DEFAULT_CONF_PATH
#define SPALE_DEFAULT_CONF_PATH      "/etc/spale/spale.conf"
#else
#define SPALE_DEFAULT_CONF_PATH      SPALE_STR(DEFAULT_CONF_PATH)
#endif

#ifndef DEFAULT_SERVER_KEY
#define SPALE_DEFAULT_SERVER_KEY     "/etc/spale/server.key"
#else
#define SPALE_DEFAULT_SERVER_KEY     SPALE_STR(DEFAULT_SERVER_KEY)
#endif

#ifndef DEFAULT_CLIENTS_DIR
#define SPALE_DEFAULT_CLIENTS_DIR    "/etc/spale/clients"
#else
#define SPALE_DEFAULT_CLIENTS_DIR    SPALE_STR(DEFAULT_CLIENTS_DIR)
#endif


