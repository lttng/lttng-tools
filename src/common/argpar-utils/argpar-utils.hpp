/*
 * SPDX-FileCopyrightText: 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef COMMON_ARGPAR_UTILS_H
#define COMMON_ARGPAR_UTILS_H

#include <common/format.hpp>
#include <common/macros.hpp>
#include <common/string-utils/format.hpp>

#include <vendor/argpar/argpar.h>

#include <stdarg.h>

#define WHILE_PARSING_ARG_N_ARG_FMT "While parsing argument #%d (`%s`): "

enum parse_next_item_status {
	PARSE_NEXT_ITEM_STATUS_OK = 0,
	PARSE_NEXT_ITEM_STATUS_END = 1,
	PARSE_NEXT_ITEM_STATUS_ERROR = -1,
	PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY = -2,
};

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<parse_next_item_status> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(parse_next_item_status status,
						    FormatContextType& ctx) const
	{
		auto name = "unknown";

		switch (status) {
		case PARSE_NEXT_ITEM_STATUS_OK:
			name = "ok";
		case PARSE_NEXT_ITEM_STATUS_END:
			name = "end";
		case PARSE_NEXT_ITEM_STATUS_ERROR:
			name = "error";
		case PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY:
			name = "allocation error";
		}

		return format_to(ctx.out(), name);
	}
};
} /* namespace fmt */

/*
 * Parse the next argpar item using `iter`.
 *
 * The item in `*item` is always freed and cleared on entry.
 *
 * If an item is parsed successfully, return the new item in `*item` and return
 * PARSE_NEXT_ITEM_STATUS_OK.
 *
 * If the end of the argument list is reached, return
 * PARSE_NEXT_ITEM_STATUS_END.
 *
 * On error, print a descriptive error message and return
 * PARSE_NEXT_ITEM_STATUS_ERROR.  If `context_fmt` is non-NULL, it is formatted
 * using the following arguments and prepended to the error message.
 * Add `argc_offset` to the argument index mentioned in the error message.
 *
 * If `unknown_opt_is_error` is true, an unknown option is considered an error.
 * Otherwise, it is considered as the end of the argument list.
 *
 * If `error_out` is given and PARSE_NEXT_ITEM_STATUS_ERROR is returned, set
 * `*error_out` to the argpar_error object corresponding to the error.  The
 * caller must free the object with `argpar_error_destroy`.
 */
ATTR_FORMAT_PRINTF(7, 8)
enum parse_next_item_status parse_next_item(struct argpar_iter *iter,
					    const struct argpar_item **item,
					    int argc_offset,
					    const char **argv,
					    bool unknown_opt_is_error,
					    const struct argpar_error **error_out,
					    const char *context_fmt,
					    ...);

#endif
