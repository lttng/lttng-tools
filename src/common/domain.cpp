/*
 * SPDX-FileCopyrightText: 2020 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "common/config/config-session-abi.hpp"
#include "common/macros.hpp"
#include "lttng/domain-internal.hpp"
#include "lttng/lttng-error.h"

enum lttng_error_code lttng_domain_type_parse(const char *str, enum lttng_domain_type *domain_type)
{
	enum lttng_domain_type dt = LTTNG_DOMAIN_NONE;

	if (!domain_type) {
		return LTTNG_ERR_INVALID;
	}

	if (strcasecmp(str, "none") == 0) {
		/* fallthrough */
	} else if (strcasecmp(str, config_domain_type_kernel) == 0) {
		dt = LTTNG_DOMAIN_KERNEL;
	} else if (strcasecmp(str, config_domain_type_ust) == 0) {
		dt = LTTNG_DOMAIN_UST;
	} else if (strcasecmp(str, config_domain_type_jul) == 0) {
		dt = LTTNG_DOMAIN_JUL;
	} else if (strcasecmp(str, config_domain_type_log4j) == 0) {
		dt = LTTNG_DOMAIN_LOG4J;
	} else if (strcasecmp(str, config_domain_type_log4j2) == 0) {
		dt = LTTNG_DOMAIN_LOG4J2;
	} else if (strcasecmp(str, config_domain_type_python) == 0) {
		dt = LTTNG_DOMAIN_PYTHON;
	} else {
		return LTTNG_ERR_UNK;
	}

	*domain_type = dt;
	return LTTNG_OK;
}

const char *lttng_domain_type_str(enum lttng_domain_type domain_type)
{
	switch (domain_type) {
	case LTTNG_DOMAIN_NONE:
		return "none";
	case LTTNG_DOMAIN_KERNEL:
		return "kernel";
	case LTTNG_DOMAIN_UST:
		return "user space";
	case LTTNG_DOMAIN_JUL:
		return "java.util.logging (JUL)";
	case LTTNG_DOMAIN_LOG4J:
		return "log4j";
	case LTTNG_DOMAIN_LOG4J2:
		return "log4j2";
	case LTTNG_DOMAIN_PYTHON:
		return "Python logging";
	default:
		return "???";
	}
}
