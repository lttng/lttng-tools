/*
 * SPDX-FileCopyrightText: 2020 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SRC_BIN_LTTNG_UPROBE_H
#define SRC_BIN_LTTNG_UPROBE_H

#include <common/macros.hpp>

struct lttng_userspace_probe_location;

int parse_userspace_probe_opts(const char *opt, struct lttng_userspace_probe_location **uprobe_loc);

#endif /* SRC_BIN_LTTNG_UPROBE_H */
