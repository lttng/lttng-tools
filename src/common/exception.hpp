/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EXCEPTION_H_
#define LTTNG_EXCEPTION_H_

#include <lttng/lttng-error.h>

#include <stdexcept>
#include <string>
#include <system_error>

#define LTTNG_THROW_CTL(msg, error_code) \
	throw lttng::ctl::error(msg, error_code, __FILE__, __func__, __LINE__)
#define LTTNG_THROW_POSIX(msg, errno_code) \
	throw lttng::posix_error(msg, errno_code, __FILE__, __func__, __LINE__)
#define LTTNG_THROW_ERROR(msg) throw lttng::runtime_error(msg, __FILE__, __func__, __LINE__)
#define LTTNG_THROW_UNSUPPORTED_ERROR(msg) \
	throw lttng::runtime_error(msg, __FILE__, __func__, __LINE__)
#define LTTNG_THROW_COMMUNICATION_ERROR(msg) \
	throw lttng::communication_error(msg, __FILE__, __func__, __LINE__)
#define LTTNG_THROW_PROTOCOL_ERROR(msg) \
	throw lttng::protocol_error(msg, __FILE__, __func__, __LINE__)
#define LTTNG_THROW_INVALID_ARGUMENT_ERROR(msg) \
	throw lttng::invalid_argument_error(msg, __FILE__, __func__, __LINE__)

namespace lttng {
class runtime_error : public std::runtime_error {
public:
	explicit runtime_error(const std::string& msg,
			       const char *file_name,
			       const char *function_name,
			       unsigned int line_number);
};

class unsupported_error : public std::runtime_error {
public:
	explicit unsupported_error(const std::string& msg,
				   const char *file_name,
				   const char *function_name,
				   unsigned int line_number);
};

namespace ctl {
/* Wrap lttng_error_code errors which may be reported through liblttng-ctl's interface. */
class error : public runtime_error {
public:
	explicit error(const std::string& msg,
		       lttng_error_code error_code,
		       const char *file_name,
		       const char *function_name,
		       unsigned int line_number);

	lttng_error_code code() const noexcept
	{
		return _error_code;
	}

private:
	const lttng_error_code _error_code;
};
} /* namespace ctl */

class posix_error : public std::system_error {
public:
	explicit posix_error(const std::string& msg,
			     int errno_code,
			     const char *file_name,
			     const char *function_name,
			     unsigned int line_number);
};

class communication_error : public runtime_error {
public:
	explicit communication_error(const std::string& msg,
				     const char *file_name,
				     const char *function_name,
				     unsigned int line_number);
};

class protocol_error : public communication_error {
public:
	explicit protocol_error(const std::string& msg,
				const char *file_name,
				const char *function_name,
				unsigned int line_number);
};

class invalid_argument_error : public runtime_error {
public:
	explicit invalid_argument_error(const std::string& msg,
					const char *file_name,
					const char *function_name,
					unsigned int line_number);
};

}; /* namespace lttng */

#endif /* LTTNG_EXCEPTION_H_ */
