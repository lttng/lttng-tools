/*
 * Copyright (C) 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "argpar-utils.hpp"

#include <common/error.hpp>
#include <common/string-utils/string-utils.hpp>

#include <stdio.h>

/*
 * Given argpar error status `status` and error `error`, return a formatted
 * error message describing the error.
 *
 * `argv` is the argument vector that was being parsed.
 *
 * `context_fmt`, if non-NULL, is formatted using `args` and prepended to the
 * error message.
 *
 * Add `argc_offset` the the argument index mentioned in the error message.
 *
 * The returned string must be freed by the caller.
 */
static ATTR_FORMAT_PRINTF(4, 0) char *format_arg_error_v(const struct argpar_error *error,
							 int argc_offset,
							 const char **argv,
							 const char *context_fmt,
							 va_list args)
{
	char *str = nullptr;
	char *str_ret = nullptr;
	int ret;

	if (context_fmt) {
		ret = vasprintf(&str, context_fmt, args);
		if (ret == -1) {
			/*
			 * If vasprintf fails, the content of str is undefined,
			 * and we shouldn't try to free it.
			 */
			str = nullptr;
			goto end;
		}

		ret = strutils_append_str(&str, ": ");
		if (ret < 0) {
			goto end;
		}
	}

	switch (argpar_error_type(error)) {
	case ARGPAR_ERROR_TYPE_MISSING_OPT_ARG:
	{
		const int orig_index = argpar_error_orig_index(error);
		const char *arg = argv[orig_index];

		ret = strutils_appendf(&str,
				       WHILE_PARSING_ARG_N_ARG_FMT
				       "Missing required argument for option `%s`",
				       orig_index + 1 + argc_offset,
				       argv[orig_index],
				       arg);
		if (ret < 0) {
			goto end;
		}

		break;
	}
	case ARGPAR_ERROR_TYPE_UNEXPECTED_OPT_ARG:
	{
		bool is_short;
		const struct argpar_opt_descr *descr = argpar_error_opt_descr(error, &is_short);
		int orig_index = argpar_error_orig_index(error);
		const char *arg = argv[orig_index];

		if (is_short) {
			ret = strutils_appendf(&str,
					       WHILE_PARSING_ARG_N_ARG_FMT
					       "Unexpected argument for option `-%c`",
					       orig_index + 1 + argc_offset,
					       arg,
					       descr->short_name);
		} else {
			ret = strutils_appendf(&str,
					       WHILE_PARSING_ARG_N_ARG_FMT
					       "Unexpected argument for option `--%s`",
					       orig_index + 1 + argc_offset,
					       arg,
					       descr->long_name);
		}

		if (ret < 0) {
			goto end;
		}

		break;
	}
	case ARGPAR_ERROR_TYPE_UNKNOWN_OPT:
	{
		int orig_index = argpar_error_orig_index(error);
		const char *unknown_opt = argpar_error_unknown_opt_name(error);

		ret = strutils_appendf(&str,
				       WHILE_PARSING_ARG_N_ARG_FMT "Unknown option `%s`",
				       orig_index + 1 + argc_offset,
				       argv[orig_index],
				       unknown_opt);

		if (ret < 0) {
			goto end;
		}

		break;
	}
	default:
		abort();
	}

	str_ret = str;
	str = nullptr;

end:
	free(str);
	return str_ret;
}

enum parse_next_item_status parse_next_item(struct argpar_iter *iter,
					    const struct argpar_item **item,
					    int argc_offset,
					    const char **argv,
					    bool unknown_opt_is_error,
					    const struct argpar_error **error_out,
					    const char *context_fmt,
					    ...)
{
	enum argpar_iter_next_status status;
	const struct argpar_error *error = nullptr;
	enum parse_next_item_status ret;

	ARGPAR_ITEM_DESTROY_AND_RESET(*item);
	status = argpar_iter_next(iter, item, &error);

	switch (status) {
	case ARGPAR_ITER_NEXT_STATUS_ERROR_MEMORY:
		ERR("Failed to get next argpar item.");
		ret = PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY;
		break;
	case ARGPAR_ITER_NEXT_STATUS_ERROR:
	{
		va_list args;
		char *err_str;

		if (argpar_error_type(error) == ARGPAR_ERROR_TYPE_UNKNOWN_OPT &&
		    !unknown_opt_is_error) {
			ret = PARSE_NEXT_ITEM_STATUS_END;
			break;
		}

		va_start(args, context_fmt);
		err_str = format_arg_error_v(error, argc_offset, argv, context_fmt, args);
		va_end(args);

		if (err_str) {
			ERR("%s", err_str);
			free(err_str);
		} else {
			ERR("%s", "Failed to format argpar error.");
		}

		ret = PARSE_NEXT_ITEM_STATUS_ERROR;
		break;
	}
	case ARGPAR_ITER_NEXT_STATUS_END:
		ret = PARSE_NEXT_ITEM_STATUS_END;
		break;
	case ARGPAR_ITER_NEXT_STATUS_OK:
		ret = PARSE_NEXT_ITEM_STATUS_OK;
		break;
	default:
		abort();
	}

	if (error_out) {
		argpar_error_destroy(*error_out);
		*error_out = error;
		error = nullptr;
	}

	argpar_error_destroy(error);

	return ret;
}
