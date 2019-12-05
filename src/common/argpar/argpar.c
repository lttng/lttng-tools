/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argpar.h"

#define argpar_realloc(_ptr, _type, _nmemb) ((_type *) realloc(_ptr, (_nmemb) * sizeof(_type)))
#define argpar_calloc(_type, _nmemb) ((_type *) calloc((_nmemb), sizeof(_type)))
#define argpar_zalloc(_type) argpar_calloc(_type, 1)

#define ARGPAR_ASSERT(_cond) assert(_cond)

#ifdef __MINGW_PRINTF_FORMAT
# define ARGPAR_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#else
# define ARGPAR_PRINTF_FORMAT printf
#endif

static __attribute__((format(ARGPAR_PRINTF_FORMAT, 1, 0)))
char *argpar_vasprintf(const char *fmt, va_list args)
{
	int len1, len2;
	char *str;
	va_list args2;

	va_copy(args2, args);

	len1 = vsnprintf(NULL, 0, fmt, args);
	if (len1 < 0) {
		str = NULL;
		goto end;
	}

	str = malloc(len1 + 1);
	if (!str) {
		goto end;
	}

	len2 = vsnprintf(str, len1 + 1, fmt, args2);

	ARGPAR_ASSERT(len1 == len2);

end:
	va_end(args2);
	return str;
}


static __attribute__((format(ARGPAR_PRINTF_FORMAT, 1, 2)))
char *argpar_asprintf(const char *fmt, ...)
{
	va_list args;
	char *str;

	va_start(args, fmt);
	str = argpar_vasprintf(fmt, args);
	va_end(args);

	return str;
}

static  __attribute__((format(ARGPAR_PRINTF_FORMAT, 2, 3)))
bool argpar_string_append_printf(char **str, const char *fmt, ...)
{
	char *new_str = NULL;
	char *addendum;
	bool success;
	va_list args;

	ARGPAR_ASSERT(str);

	va_start(args, fmt);
	addendum = argpar_vasprintf(fmt, args);
	va_end(args);

	if (!addendum) {
		success = false;
		goto end;
	}

	new_str = argpar_asprintf("%s%s", *str ? *str : "", addendum);
	if (!new_str) {
		success = false;
		goto end;
	}

	free(*str);
	*str = new_str;

	success = true;

end:
	free(addendum);

	return success;
}

static
void destroy_item(struct argpar_item * const item)
{
	if (!item) {
		goto end;
	}

	if (item->type == ARGPAR_ITEM_TYPE_OPT) {
		struct argpar_item_opt * const opt_item = (void *) item;

		free((void *) opt_item->arg);
	}

	free(item);

end:
	return;
}

static
bool push_item(struct argpar_item_array * const array,
		struct argpar_item * const item)
{
	bool success;

	ARGPAR_ASSERT(array);
	ARGPAR_ASSERT(item);

	if (array->n_items == array->n_alloc) {
		unsigned int new_n_alloc = array->n_alloc * 2;
		struct argpar_item **new_items;

		new_items = argpar_realloc(array->items,
			struct argpar_item *, new_n_alloc);
		if (!new_items) {
			success = false;
			goto end;
		}

		array->n_alloc = new_n_alloc;
		array->items = new_items;
	}

	array->items[array->n_items] = item;
	array->n_items++;

	success = true;

end:
	return success;
}

static
void destroy_item_array(struct argpar_item_array * const array)
{
	if (array) {
		unsigned int i;

		for (i = 0; i < array->n_items; i++) {
			destroy_item(array->items[i]);
		}

		free(array->items);
		free(array);
	}
}

static
struct argpar_item_array *new_item_array(void)
{
	struct argpar_item_array *ret;
	const int initial_size = 10;

	ret = argpar_zalloc(struct argpar_item_array);
	if (!ret) {
		goto end;
	}

	ret->items = argpar_calloc(struct argpar_item *, initial_size);
	if (!ret->items) {
		goto error;
	}

	ret->n_alloc = initial_size;

	goto end;

error:
	destroy_item_array(ret);
	ret = NULL;

end:
	return ret;
}

static
struct argpar_item_opt *create_opt_item(
		const struct argpar_opt_descr * const descr,
		const char * const arg)
{
	struct argpar_item_opt *opt_item =
		argpar_zalloc(struct argpar_item_opt);

	if (!opt_item) {
		goto end;
	}

	opt_item->base.type = ARGPAR_ITEM_TYPE_OPT;
	opt_item->descr = descr;

	if (arg) {
		opt_item->arg = strdup(arg);
		if (!opt_item->arg) {
			goto error;
		}
	}

	goto end;

error:
	destroy_item(&opt_item->base);
	opt_item = NULL;

end:
	return opt_item;
}

static
struct argpar_item_non_opt *create_non_opt_item(const char * const arg,
		const unsigned int orig_index,
		const unsigned int non_opt_index)
{
	struct argpar_item_non_opt * const non_opt_item =
		argpar_zalloc(struct argpar_item_non_opt);

	if (!non_opt_item) {
		goto end;
	}

	non_opt_item->base.type = ARGPAR_ITEM_TYPE_NON_OPT;
	non_opt_item->arg = arg;
	non_opt_item->orig_index = orig_index;
	non_opt_item->non_opt_index = non_opt_index;

end:
	return non_opt_item;
}

static
const struct argpar_opt_descr *find_descr(
		const struct argpar_opt_descr * const descrs,
		const char short_name, const char * const long_name)
{
	const struct argpar_opt_descr *descr;

	for (descr = descrs; descr->short_name || descr->long_name; descr++) {
		if (short_name && descr->short_name &&
				short_name == descr->short_name) {
			goto end;
		}

		if (long_name && descr->long_name &&
				strcmp(long_name, descr->long_name) == 0) {
			goto end;
		}
	}

end:
	return !descr->short_name && !descr->long_name ? NULL : descr;
}

enum parse_orig_arg_opt_ret {
	PARSE_ORIG_ARG_OPT_RET_OK,
	PARSE_ORIG_ARG_OPT_RET_ERROR_UNKNOWN_OPT = -2,
	PARSE_ORIG_ARG_OPT_RET_ERROR = -1,
};

static
enum parse_orig_arg_opt_ret parse_short_opts(const char * const short_opts,
		const char * const next_orig_arg,
		const struct argpar_opt_descr * const descrs,
		struct argpar_parse_ret * const parse_ret,
		bool * const used_next_orig_arg)
{
	enum parse_orig_arg_opt_ret ret = PARSE_ORIG_ARG_OPT_RET_OK;
	const char *short_opt_ch = short_opts;

	if (strlen(short_opts) == 0) {
		argpar_string_append_printf(&parse_ret->error, "Invalid argument");
		goto error;
	}

	while (*short_opt_ch) {
		const char *opt_arg = NULL;
		const struct argpar_opt_descr *descr;
		struct argpar_item_opt *opt_item;

		/* Find corresponding option descriptor */
		descr = find_descr(descrs, *short_opt_ch, NULL);
		if (!descr) {
			ret = PARSE_ORIG_ARG_OPT_RET_ERROR_UNKNOWN_OPT;
			argpar_string_append_printf(&parse_ret->error,
				"Unknown option `-%c`", *short_opt_ch);
			goto error;
		}

		if (descr->with_arg) {
			if (short_opt_ch[1]) {
				/* `-oarg` form */
				opt_arg = &short_opt_ch[1];
			} else {
				/* `-o arg` form */
				opt_arg = next_orig_arg;
				*used_next_orig_arg = true;
			}

			/*
			 * We accept `-o ''` (empty option's argument),
			 * but not `-o` alone if an option's argument is
			 * expected.
			 */
			if (!opt_arg || (short_opt_ch[1] && strlen(opt_arg) == 0)) {
				argpar_string_append_printf(&parse_ret->error,
					"Missing required argument for option `-%c`",
					*short_opt_ch);
				*used_next_orig_arg = false;
				goto error;
			}
		}

		/* Create and append option argument */
		opt_item = create_opt_item(descr, opt_arg);
		if (!opt_item) {
			goto error;
		}

		if (!push_item(parse_ret->items, &opt_item->base)) {
			goto error;
		}

		if (descr->with_arg) {
			/* Option has an argument: no more options */
			break;
		}

		/* Go to next short option */
		short_opt_ch++;
	}

	goto end;

error:
	if (ret == PARSE_ORIG_ARG_OPT_RET_OK) {
		ret = PARSE_ORIG_ARG_OPT_RET_ERROR;
	}

end:
	return ret;
}

static
enum parse_orig_arg_opt_ret parse_long_opt(const char * const long_opt_arg,
		const char * const next_orig_arg,
		const struct argpar_opt_descr * const descrs,
		struct argpar_parse_ret * const parse_ret,
		bool * const used_next_orig_arg)
{
	const size_t max_len = 127;
	enum parse_orig_arg_opt_ret ret = PARSE_ORIG_ARG_OPT_RET_OK;
	const struct argpar_opt_descr *descr;
	struct argpar_item_opt *opt_item;

	/* Option's argument, if any */
	const char *opt_arg = NULL;

	/* Position of first `=`, if any */
	const char *eq_pos;

	/* Buffer holding option name when `long_opt_arg` contains `=` */
	char buf[max_len + 1];

	/* Option name */
	const char *long_opt_name = long_opt_arg;

	if (strlen(long_opt_arg) == 0) {
		argpar_string_append_printf(&parse_ret->error,
			"Invalid argument");
		goto error;
	}

	/* Find the first `=` in original argument */
	eq_pos = strchr(long_opt_arg, '=');
	if (eq_pos) {
		const size_t long_opt_name_size = eq_pos - long_opt_arg;

		/* Isolate the option name */
		if (long_opt_name_size > max_len) {
			argpar_string_append_printf(&parse_ret->error,
				"Invalid argument `--%s`", long_opt_arg);
			goto error;
		}

		memcpy(buf, long_opt_arg, long_opt_name_size);
		buf[long_opt_name_size] = '\0';
		long_opt_name = buf;
	}

	/* Find corresponding option descriptor */
	descr = find_descr(descrs, '\0', long_opt_name);
	if (!descr) {
		argpar_string_append_printf(&parse_ret->error,
			"Unknown option `--%s`", long_opt_name);
		ret = PARSE_ORIG_ARG_OPT_RET_ERROR_UNKNOWN_OPT;
		goto error;
	}

	/* Find option's argument if any */
	if (descr->with_arg) {
		if (eq_pos) {
			/* `--long-opt=arg` style */
			opt_arg = eq_pos + 1;
		} else {
			/* `--long-opt arg` style */
			if (!next_orig_arg) {
				argpar_string_append_printf(&parse_ret->error,
					"Missing required argument for option `--%s`",
					long_opt_name);
				goto error;
			}

			opt_arg = next_orig_arg;
			*used_next_orig_arg = true;
		}
	}

	/* Create and append option argument */
	opt_item = create_opt_item(descr, opt_arg);
	if (!opt_item) {
		goto error;
	}

	if (!push_item(parse_ret->items, &opt_item->base)) {
		goto error;
	}

	goto end;

error:
	if (ret == PARSE_ORIG_ARG_OPT_RET_OK) {
		ret = PARSE_ORIG_ARG_OPT_RET_ERROR;
	}

end:
	return ret;
}

static
enum parse_orig_arg_opt_ret parse_orig_arg_opt(const char * const orig_arg,
		const char * const next_orig_arg,
		const struct argpar_opt_descr * const descrs,
		struct argpar_parse_ret * const parse_ret,
		bool * const used_next_orig_arg)
{
	enum parse_orig_arg_opt_ret ret = PARSE_ORIG_ARG_OPT_RET_OK;

	ARGPAR_ASSERT(orig_arg[0] == '-');

	if (orig_arg[1] == '-') {
		/* Long option */
		ret = parse_long_opt(&orig_arg[2],
			next_orig_arg, descrs, parse_ret,
			used_next_orig_arg);
	} else {
		/* Short option */
		ret = parse_short_opts(&orig_arg[1],
			next_orig_arg, descrs, parse_ret,
			used_next_orig_arg);
	}

	return ret;
}

static
bool prepend_while_parsing_arg_to_error(char **error,
		const unsigned int i, const char * const arg)
{
	char *new_error;
	bool success;

	ARGPAR_ASSERT(error);
	ARGPAR_ASSERT(*error);

	new_error = argpar_asprintf("While parsing argument #%u (`%s`): %s",
		i + 1, arg, *error);
	if (!new_error) {
		success = false;
		goto end;
	}

	free(*error);
	*error = new_error;
	success = true;

end:
	return success;
}

ARGPAR_HIDDEN
struct argpar_parse_ret argpar_parse(unsigned int argc,
		const char * const *argv,
		const struct argpar_opt_descr * const descrs,
		bool fail_on_unknown_opt)
{
	struct argpar_parse_ret parse_ret = { 0 };
	unsigned int i;
	unsigned int non_opt_index = 0;

	parse_ret.items = new_item_array();
	if (!parse_ret.items) {
		goto error;
	}

	for (i = 0; i < argc; i++) {
		enum parse_orig_arg_opt_ret parse_orig_arg_opt_ret;
		bool used_next_orig_arg = false;
		const char * const orig_arg = argv[i];
		const char * const next_orig_arg =
			i < argc - 1 ? argv[i + 1] : NULL;

		if (orig_arg[0] != '-') {
			/* Non-option argument */
			struct argpar_item_non_opt *non_opt_item =
				create_non_opt_item(orig_arg, i, non_opt_index);

			if (!non_opt_item) {
				goto error;
			}

			non_opt_index++;

			if (!push_item(parse_ret.items, &non_opt_item->base)) {
				goto error;
			}

			continue;
		}

		/* Option argument */
		parse_orig_arg_opt_ret = parse_orig_arg_opt(orig_arg,
			next_orig_arg, descrs, &parse_ret, &used_next_orig_arg);
		switch (parse_orig_arg_opt_ret) {
		case PARSE_ORIG_ARG_OPT_RET_OK:
			break;
		case PARSE_ORIG_ARG_OPT_RET_ERROR_UNKNOWN_OPT:
			ARGPAR_ASSERT(!used_next_orig_arg);

			if (fail_on_unknown_opt) {
				prepend_while_parsing_arg_to_error(
					&parse_ret.error, i, orig_arg);
				goto error;
			}

			/*
			 * The current original argument is not
			 * considered ingested because it triggered an
			 * unknown option.
			 */
			parse_ret.ingested_orig_args = i;
			free(parse_ret.error);
			parse_ret.error = NULL;
			goto end;
		case PARSE_ORIG_ARG_OPT_RET_ERROR:
			prepend_while_parsing_arg_to_error(
				&parse_ret.error, i, orig_arg);
			goto error;
		default:
			abort();
		}

		if (used_next_orig_arg) {
			i++;
		}
	}

	parse_ret.ingested_orig_args = argc;
	free(parse_ret.error);
	parse_ret.error = NULL;
	goto end;

error:
	/* That's how we indicate that an error occurred */
	destroy_item_array(parse_ret.items);
	parse_ret.items = NULL;

end:
	return parse_ret;
}

ARGPAR_HIDDEN
void argpar_parse_ret_fini(struct argpar_parse_ret *ret)
{
	ARGPAR_ASSERT(ret);

	destroy_item_array(ret->items);
	ret->items = NULL;

	free(ret->error);
	ret->error = NULL;
}
