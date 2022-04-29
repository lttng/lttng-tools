/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EXCEPTION_H_
#define LTTNG_EXCEPTION_H_

#include <string>
#include <stdexcept>
#include <system_error>

#include <lttng/lttng-error.h>

#define LTTNG_THROW_CTL(error_code) \
	throw lttng::ctl::error(msg, error_code, __FILE__, __func__, __LINE__)
#define LTTNG_THROW_POSIX(msg, errno_code) \
	throw lttng::posix_error(msg, errno_code, __FILE__, __func__, __LINE__)

namespace lttng {

namespace ctl {
/* Wrap lttng_error_code errors which may be reported through liblttng-ctl's interface. */
class error : public std::runtime_error {
public:
	explicit error(lttng_error_code error_code,
		const char *file_name,
		const char *function_name,
		unsigned int line_number);
	lttng_error_code get_code() const;

private:
	lttng_error_code _error_code;
};
} /* namespace ctl */

class posix_error : public std::system_error {
public:
	explicit posix_error(const std::string &msg,
		int errno_code,
		const char *file_name,
		const char *function_name,
		unsigned int line_number);
};

}; /* namespace lttng */

#endif /* LTTNG_EXCEPTION_H_ */
