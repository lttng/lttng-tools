/*
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SAVE_H
#define SAVE_H

#include <common/compat/socket.hpp>
#include <common/exception.hpp>

#include <lttng/save.h>

#define LTTNG_THROW_SAVE_ERROR(msg) \
	throw lttng::sessiond::exceptions::save_error(msg, LTTNG_SOURCE_LOCATION())

namespace lttng {
namespace sessiond {
namespace exceptions {

/*
 * @class save_error
 * @brief Represents a session save I/O failure.
 *
 * Thrown when a session configuration cannot be serialized to XML.
 */
class save_error : public lttng::runtime_error {
public:
	explicit save_error(const std::string& msg, const lttng::source_location& location) :
		lttng::runtime_error(msg, location)
	{
	}
};

} /* namespace exceptions */
} /* namespace sessiond */
} /* namespace lttng */

int cmd_save_sessions(struct lttng_save_session_attr *attr, lttng_sock_cred *creds);

#endif /* SAVE_H */
