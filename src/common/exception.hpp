/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EXCEPTION_H_
#define LTTNG_EXCEPTION_H_

#include <common/string-utils/c-string-view.hpp>

#include <lttng/lttng-error.h>

#include <vendor/optional.hpp>

#include <stdexcept>
#include <string>
#include <system_error>

#define LTTNG_SOURCE_LOCATION() lttng::source_location(__FILE__, __func__, __LINE__)

#define LTTNG_THROW_CTL(msg, error_code) \
	throw lttng::ctl::error(msg, error_code, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_POSIX(msg, errno_code) \
	throw lttng::posix_error(msg, errno_code, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_ERROR(msg)	      throw lttng::runtime_error(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_OUT_OF_RANGE(msg) throw lttng::out_of_range(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_ALLOCATION_FAILURE_ERROR(msg) \
	throw lttng::allocation_failure(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(msg, allocation_size) \
	throw lttng::allocation_failure(msg, allocation_size, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_UNSUPPORTED_ERROR(msg) \
	throw lttng::unsupported_error(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_COMMUNICATION_ERROR(msg) \
	throw lttng::communication_error(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_PROTOCOL_ERROR(msg) throw lttng::protocol_error(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_INVALID_ARGUMENT_ERROR(msg) \
	throw lttng::invalid_argument_error(msg, LTTNG_SOURCE_LOCATION())

namespace lttng {
/*
 * @class source_location
 * @brief Represents the location in the source code where an exception was thrown.
 *
 * The source_location class captures the file name, function name, and line number
 * of the source code where an exception occurs. This information is useful for
 * debugging and logging purposes.
 *
 * @details
 * This class provides:
 * - The name of the source file (file_name).
 * - The name of the function (function_name).
 * - The line number in the source file (line_number).
 *
 * Example usage:
 * @code
 * try {
 *     // Code that may throw an exception.
 * } catch (const lttng::runtime_error& ex) {
 *     // Handle the exception, possibly logging location information.
 *     ERR_FMT("{} [{}]", ex.what(), ex.source_location);
 * }
 * @endcode
 */
class source_location {
public:
	source_location(lttng::c_string_view file_name_,
			lttng::c_string_view function_name_,
			unsigned int line_number_) :
		file_name(file_name_), function_name(function_name_), line_number(line_number_)
	{
	}

	lttng::c_string_view file_name;
	lttng::c_string_view function_name;
	unsigned int line_number;
};

/*
 * @class runtime_error
 * @brief Base type for all LTTng exceptions.
 *
 * Exceptions in the project provide an error message (through the usual what() method), but that
 * message may not include the whole context of the error. For example, it is not always desirable
 * to include the source location in a user-facing message.
 *
 * As such, exception handlers should mind the type of the exception being thrown and consider
 * what context is suitable to extract (e.g. some context may only be relevant at the DEBUG logging
 * level, while the error message may be user-facing).
 *
 * Since 'what()' is marked as noexcept, derived classes should format their generic message during
 * their construction and pass it to the runtime_error constructor.
 */
class runtime_error : public std::runtime_error {
public:
	runtime_error(const std::string& msg, const lttng::source_location& source_location);

	lttng::source_location source_location;
};

/*
 * @class allocation_failure
 * @brief Represents an allocation failure.
 *
 * Thrown when an allocation fails. Differs from bad_alloc in that it offers a message and a
 * source location.
 */
class allocation_failure : public lttng::runtime_error {
public:
	explicit allocation_failure(const std::string& msg,
				    const lttng::source_location& source_location);
	explicit allocation_failure(const std::string& msg,
				    std::size_t allocation_size,
				    const lttng::source_location& source_location);

	nonstd::optional<std::size_t> allocation_size;
};

/*
 * @class out_of_range
 * @brief Represents an out of range access error.
 *
 * Thrown when attempting to access a container out of its valid range (e.g., advancing an iterator
 * past end()).
 */
class out_of_range : public lttng::runtime_error {
public:
	explicit out_of_range(const std::string& msg,
			      const lttng::source_location& source_location);
};

/*
 * @class unsupported_error
 * @brief Represents an error for unsupported features.
 *
 * This error may occur due to the current configuration making a feature unavailable
 * (e.g. when using an older kernel or tracer release).
 */
class unsupported_error : public lttng::runtime_error {
public:
	explicit unsupported_error(const std::string& msg,
				   const lttng::source_location& source_location);
};

namespace ctl {
/*
 * @class error
 * @brief Wraps lttng_error_code errors for reporting through liblttng-ctl's interface.
 *
 * There is typically a better way to report errors than using this type of exception. However, it
 * is sometimes useful to transition legacy code to use RAII facilities and exceptions without
 * revisiting every caller.
 */
class error : public runtime_error {
public:
	explicit error(const std::string& msg,
		       lttng_error_code error_code,
		       const lttng::source_location& source_location);

	lttng_error_code code() const noexcept
	{
		return _error_code;
	}

private:
	const lttng_error_code _error_code;
};
} /* namespace ctl */

/*
 * @class posix_error
 * @brief Wraps a POSIX system error, including the location where the error occurred.
 */
class posix_error : public std::system_error, lttng::runtime_error {
public:
	explicit posix_error(const std::string& msg,
			     unsigned int errno_code,
			     const lttng::source_location& source_location);
};

/*
 * @class communication_error
 * @brief Base class for communication errors between components.
 */
class communication_error : public lttng::runtime_error {
public:
	explicit communication_error(const std::string& msg,
				     const lttng::source_location& source_location);
};

/*
 * @class protocol_error
 * @brief Base class for protocol layer communication errors (encoding or decoding problems).
 */
class protocol_error : public communication_error {
public:
	explicit protocol_error(const std::string& msg,
				const lttng::source_location& source_location);
};

/*
 * @class invalid_argument_error
 * @brief Represents an error for invalid arguments.
 */
class invalid_argument_error : public lttng::runtime_error {
public:
	explicit invalid_argument_error(const std::string& msg,
					const lttng::source_location& source_location);
};

} /* namespace lttng */

/*
 * Specialize fmt::formatter for lttng::source_location
 *
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::source_location> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const lttng::source_location& location,
						    FormatContextType& ctx) const
	{
		return format_to(ctx.out(),
				 "{}() {}:{}",
				 location.function_name.data(),
				 location.file_name.data(),
				 location.line_number);
	}
};
} /* namespace fmt */

#endif /* LTTNG_EXCEPTION_H_ */
