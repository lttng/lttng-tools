/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "trace-ust.hpp"

#include <common/error.hpp>

#include <lttng/ust-ctl.h>

bool trace_ust_runtime_ctl_version_matches_build_version()
{
	uint32_t major, minor, patch_level;

	if (lttng_ust_ctl_get_version(&major, &minor, &patch_level)) {
		ERR("Failed to get liblttng-ust-ctl.so version");
		return false;
	}

	if (major != VERSION_MAJOR || minor != VERSION_MINOR) {
		ERR_FMT("Mismatch between liblttng-ust-ctl.so runtime version ({}.{}) and build version ({}.{})",
			major,
			minor,
			VERSION_MAJOR,
			VERSION_MINOR);
		return false;
	}

	return true;
}
