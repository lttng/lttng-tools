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

#include <stdexcept>
#include <string>

#define LTTNG_THROW_CLI_NO_DEFAULT_SESSION() \
	throw lttng::cli::no_default_session_error(LTTNG_SOURCE_LOCATION())

namespace lttng {
namespace cli {
class no_default_session_error : public runtime_error {
public:
	explicit no_default_session_error(const lttng::source_location& source_location);
};
} /* namespace cli */
}; /* namespace lttng */

#endif /* LTTNG_CLI_EXCEPTION_H */
