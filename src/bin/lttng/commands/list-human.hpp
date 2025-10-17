/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_LIST_HUMAN_HPP
#define _LTTNG_LIST_HUMAN_HPP

#include "list-common.hpp"

/*
 * Pretty-print (human-readable) output for the list command.
 *
 * Returns CMD_SUCCESS on success, appropriate error code otherwise.
 */
int list_human(const list_cmd_config& config);

#endif /* _LTTNG_LIST_HUMAN_HPP */
