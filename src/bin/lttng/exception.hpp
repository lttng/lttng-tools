/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CLI_EXCEPTION_H
#define LTTNG_CLI_EXCEPTION_H

#include <common/exception.hpp>

#include <lttng/lttng-error.h>

#include <string>

#define LTTNG_THROW_CLI_NO_DEFAULT_SESSION() \
	throw lttng::cli::no_default_session_error(LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_CLI_INVALID_USAGE(msg) \
	throw lttng::cli::invalid_usage_error(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_CLI_SHOW_HELP_FAIL(command_name) \
	throw lttng::cli::show_help_failure(command_name, LTTNG_SOURCE_LOCATION())

namespace lttng {
namespace cli {
class no_default_session_error : public runtime_error {
public:
	explicit no_default_session_error(const lttng::source_location& source_location);
};

class invalid_usage_error : public runtime_error {
public:
	explicit invalid_usage_error(const std::string& msg,
				     const lttng::source_location& source_location);
};

class show_help_failure : public runtime_error {
public:
	explicit show_help_failure(const char *command_name,
				   const lttng::source_location& source_location);
};
} /* namespace cli */
}; /* namespace lttng */

#endif /* LTTNG_CLI_EXCEPTION_H */
