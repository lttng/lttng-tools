/*
 * SPDX-FileCopyrightText: 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/logging-utils.hpp>

#include <sys/utsname.h>

/* Output system information as logging statements. */
void lttng::logging::log_system_information(lttng_error_level error_level)
{
	struct utsname name = {};
	const int ret = uname(&name);

	if (ret) {
		PERROR("Failed to get system information using uname()")
		return;
	}

	LOG(error_level, "System information:");
	LOG(error_level, "\tsysname: `%s`", name.sysname);
	LOG(error_level, "\tnodename: `%s`", name.nodename);
	LOG(error_level, "\trelease: `%s`", name.release);
	LOG(error_level, "\tversion: `%s`", name.version);
	LOG(error_level, "\tmachine: `%s`", name.machine);
}
