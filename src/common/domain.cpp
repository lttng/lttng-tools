/*
 * SPDX-FileCopyrightText: 2020 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "common/config/config-session-abi.hpp"
#include "lttng/domain-internal.hpp"
#include "lttng/lttng-error.h"

#include <common/domain.hpp>
#include <common/exception.hpp>

enum lttng_error_code lttng_domain_type_parse(const char *str, enum lttng_domain_type *domain_type)
{
	enum lttng_domain_type dt = LTTNG_DOMAIN_NONE;

	if (!domain_type) {
		return LTTNG_ERR_INVALID;
	}

	if (strcmp(str, "kernel") == 0) {
		dt = LTTNG_DOMAIN_KERNEL;
	} else if (strcmp(str, "user") == 0) {
		dt = LTTNG_DOMAIN_UST;
	} else if (strcmp(str, "jul") == 0) {
		dt = LTTNG_DOMAIN_JUL;
	} else if (strcmp(str, "log4j") == 0) {
		dt = LTTNG_DOMAIN_LOG4J;
	} else if (strcmp(str, "log4j2") == 0) {
		dt = LTTNG_DOMAIN_LOG4J2;
	} else if (strcmp(str, "python") == 0) {
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

lttng::domain_class
lttng::get_domain_class_from_lttng_domain_type(enum lttng_domain_type domain_type)
{
	switch (domain_type) {
	case LTTNG_DOMAIN_KERNEL:
		return lttng::domain_class::KERNEL_SPACE;
	case LTTNG_DOMAIN_UST:
		return lttng::domain_class::USER_SPACE;
	case LTTNG_DOMAIN_JUL:
		return lttng::domain_class::JAVA_UTIL_LOGGING;
	case LTTNG_DOMAIN_LOG4J:
		return lttng::domain_class::LOG4J;
	case LTTNG_DOMAIN_PYTHON:
		return lttng::domain_class::PYTHON_LOGGING;
	case LTTNG_DOMAIN_LOG4J2:
		return lttng::domain_class::LOG4J2;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"No suitable conversion exists from lttng_domain_type enum to lttng::domain_class");
	}
}
