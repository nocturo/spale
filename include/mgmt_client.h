// SPDX-License-Identifier: MIT
#pragma once

// Send a management request to the running daemon and print response to stdout.
// Returns 0 on success, -1 on error.
int mgmt_client_request(const char *req);

// Manage subcommand entrypoint: manage <list|authorize|allowlist> ...
int manage_main(int argc, char **argv);


