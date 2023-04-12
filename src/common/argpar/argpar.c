/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2019-2021 Philippe Proulx <pproulx@efficios.com>
 * Copyright (c) 2020-2021 Simon Marchi <simon.marchi@efficios.com>
 */

#include "argpar.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARGPAR_REALLOC(_ptr, _type, _nmemb) ((_type *) realloc(_ptr, (_nmemb) * sizeof(_type)))

#define ARGPAR_CALLOC(_type, _nmemb) ((_type *) calloc((_nmemb), sizeof(_type)))

#define ARGPAR_ZALLOC(_type) ARGPAR_CALLOC(_type, 1)

#ifdef NDEBUG
/*
 * Force usage of the assertion condition to prevent unused variable warnings
 * when `assert()` are disabled by the `NDEBUG` definition.
 */
#define ARGPAR_ASSERT(_cond) ((void) sizeof((void) (_cond), 0))
#else
#include <assert.h>
#define ARGPAR_ASSERT(_cond) assert(_cond)
#endif

/*
 * An argpar iterator.
 *
 * Such a structure contains the state of an iterator between calls to
 * argpar_iter_next().
 */
struct argpar_iter {
	/*
	 * Data provided by the user to argpar_iter_create(); immutable
	 * afterwards.
	 */
	struct {
		unsigned int argc;
		const char *const *argv;
		const struct argpar_opt_descr *descrs;
	} user;

	/*
	 * Index of the argument to process in the next
	 * argpar_iter_next() call.
	 */
	unsigned int i;

	/* Counter of non-option arguments */
	int non_opt_index;

	/*
	 * Current character within the current short option group: if
	 * it's not `NULL`, the parser is within a short option group,
	 * therefore it must resume there in the next argpar_iter_next()
	 * call.
	 */
	const char *short_opt_group_ch;

	/* Temporary character buffer which only grows */
	struct {
		size_t size;
		char *data;
	} tmp_buf;
};

/* Base parsing item */
struct argpar_item {
	enum argpar_item_type type;
};

/* Option parsing item */
struct argpar_item_opt {
	struct argpar_item base;

	/* Corresponding descriptor */
	const struct argpar_opt_descr *descr;

	/* Argument, or `NULL` if none; owned by this */
	char *arg;
};

/* Non-option parsing item */
struct argpar_item_non_opt {
	struct argpar_item base;

	/*
	 * Complete argument, pointing to one of the entries of the
	 * original arguments (`argv`).
	 */
	const char *arg;

	/*
	 * Index of this argument amongst all original arguments
	 * (`argv`).
	 */
	unsigned int orig_index;

	/* Index of this argument amongst other non-option arguments */
	unsigned int non_opt_index;
};

/* Parsing error */
struct argpar_error {
	/* Error type */
	enum argpar_error_type type;

	/* Original argument index */
	unsigned int orig_index;

	/* Name of unknown option; owned by this */
	char *unknown_opt_name;

	/* Option descriptor */
	const struct argpar_opt_descr *opt_descr;

	/* `true` if a short option caused the error */
	bool is_short;
};

ARGPAR_HIDDEN
enum argpar_item_type argpar_item_type(const struct argpar_item *const item)
{
	ARGPAR_ASSERT(item);
	return item->type;
}

ARGPAR_HIDDEN
const struct argpar_opt_descr *argpar_item_opt_descr(const struct argpar_item *const item)
{
	ARGPAR_ASSERT(item);
	ARGPAR_ASSERT(item->type == ARGPAR_ITEM_TYPE_OPT);
	return ((const struct argpar_item_opt *) item)->descr;
}

ARGPAR_HIDDEN
const char *argpar_item_opt_arg(const struct argpar_item *const item)
{
	ARGPAR_ASSERT(item);
	ARGPAR_ASSERT(item->type == ARGPAR_ITEM_TYPE_OPT);
	return ((const struct argpar_item_opt *) item)->arg;
}

ARGPAR_HIDDEN
const char *argpar_item_non_opt_arg(const struct argpar_item *const item)
{
	ARGPAR_ASSERT(item);
	ARGPAR_ASSERT(item->type == ARGPAR_ITEM_TYPE_NON_OPT);
	return ((const struct argpar_item_non_opt *) item)->arg;
}

ARGPAR_HIDDEN
unsigned int argpar_item_non_opt_orig_index(const struct argpar_item *const item)
{
	ARGPAR_ASSERT(item);
	ARGPAR_ASSERT(item->type == ARGPAR_ITEM_TYPE_NON_OPT);
	return ((const struct argpar_item_non_opt *) item)->orig_index;
}

ARGPAR_HIDDEN
unsigned int argpar_item_non_opt_non_opt_index(const struct argpar_item *const item)
{
	ARGPAR_ASSERT(item);
	ARGPAR_ASSERT(item->type == ARGPAR_ITEM_TYPE_NON_OPT);
	return ((const struct argpar_item_non_opt *) item)->non_opt_index;
}

ARGPAR_HIDDEN
void argpar_item_destroy(const struct argpar_item *const item)
{
	if (!item) {
		goto end;
	}

	if (item->type == ARGPAR_ITEM_TYPE_OPT) {
		struct argpar_item_opt *const opt_item = (struct argpar_item_opt *) item;

		free(opt_item->arg);
	}

	free((void *) item);

end:
	return;
}

/*
 * Creates and returns an option parsing item for the descriptor `descr`
 * and having the argument `arg` (copied; may be `NULL`).
 *
 * Returns `NULL` on memory error.
 */
static struct argpar_item_opt *create_opt_item(const struct argpar_opt_descr *const descr,
					       const char *const arg)
{
	struct argpar_item_opt *opt_item = ARGPAR_ZALLOC(struct argpar_item_opt);

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
	argpar_item_destroy(&opt_item->base);
	opt_item = NULL;

end:
	return opt_item;
}

/*
 * Creates and returns a non-option parsing item for the original
 * argument `arg` having the original index `orig_index` and the
 * non-option index `non_opt_index`.
 *
 * Returns `NULL` on memory error.
 */
static struct argpar_item_non_opt *create_non_opt_item(const char *const arg,
						       const unsigned int orig_index,
						       const unsigned int non_opt_index)
{
	struct argpar_item_non_opt *const non_opt_item = ARGPAR_ZALLOC(struct argpar_item_non_opt);

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

/*
 * If `error` is not `NULL`, sets the error `error` to a new parsing
 * error object, setting its `unknown_opt_name`, `opt_descr`, and
 * `is_short` members from the parameters.
 *
 * `unknown_opt_name` is the unknown option name without any `-` or `--`
 * prefix: `is_short` controls which type of unknown option it is.
 *
 * Returns 0 on success (including if `error` is `NULL`) or -1 on memory
 * error.
 */
static int set_error(struct argpar_error **const error,
		     enum argpar_error_type type,
		     const char *const unknown_opt_name,
		     const struct argpar_opt_descr *const opt_descr,
		     const bool is_short)
{
	int ret = 0;

	if (!error) {
		goto end;
	}

	*error = ARGPAR_ZALLOC(struct argpar_error);
	if (!*error) {
		goto error;
	}

	(*error)->type = type;

	if (unknown_opt_name) {
		(*error)->unknown_opt_name =
			ARGPAR_CALLOC(char, strlen(unknown_opt_name) + 1 + (is_short ? 1 : 2));
		if (!(*error)->unknown_opt_name) {
			goto error;
		}

		if (is_short) {
			strcpy((*error)->unknown_opt_name, "-");
		} else {
			strcpy((*error)->unknown_opt_name, "--");
		}

		strcat((*error)->unknown_opt_name, unknown_opt_name);
	}

	(*error)->opt_descr = opt_descr;
	(*error)->is_short = is_short;
	goto end;

error:
	argpar_error_destroy(*error);
	ret = -1;

end:
	return ret;
}

ARGPAR_HIDDEN
enum argpar_error_type argpar_error_type(const struct argpar_error *const error)
{
	ARGPAR_ASSERT(error);
	return error->type;
}

ARGPAR_HIDDEN
unsigned int argpar_error_orig_index(const struct argpar_error *const error)
{
	ARGPAR_ASSERT(error);
	return error->orig_index;
}

ARGPAR_HIDDEN
const char *argpar_error_unknown_opt_name(const struct argpar_error *const error)
{
	ARGPAR_ASSERT(error);
	ARGPAR_ASSERT(error->type == ARGPAR_ERROR_TYPE_UNKNOWN_OPT);
	ARGPAR_ASSERT(error->unknown_opt_name);
	return error->unknown_opt_name;
}

ARGPAR_HIDDEN
const struct argpar_opt_descr *argpar_error_opt_descr(const struct argpar_error *const error,
						      bool *const is_short)
{
	ARGPAR_ASSERT(error);
	ARGPAR_ASSERT(error->type == ARGPAR_ERROR_TYPE_MISSING_OPT_ARG ||
		      error->type == ARGPAR_ERROR_TYPE_UNEXPECTED_OPT_ARG);
	ARGPAR_ASSERT(error->opt_descr);

	if (is_short) {
		*is_short = error->is_short;
	}

	return error->opt_descr;
}

ARGPAR_HIDDEN
void argpar_error_destroy(const struct argpar_error *const error)
{
	if (error) {
		free(error->unknown_opt_name);
		free((void *) error);
	}
}

/*
 * Finds and returns the _first_ descriptor having the short option name
 * `short_name` or the long option name `long_name` within the option
 * descriptors `descrs`.
 *
 * `short_name` may be `'\0'` to not consider it.
 *
 * `long_name` may be `NULL` to not consider it.
 *
 * Returns `NULL` if no descriptor is found.
 */
static const struct argpar_opt_descr *find_descr(const struct argpar_opt_descr *const descrs,
						 const char short_name,
						 const char *const long_name)
{
	const struct argpar_opt_descr *descr;

	for (descr = descrs; descr->short_name || descr->long_name; descr++) {
		if (short_name && descr->short_name && short_name == descr->short_name) {
			goto end;
		}

		if (long_name && descr->long_name && strcmp(long_name, descr->long_name) == 0) {
			goto end;
		}
	}

end:
	return !descr->short_name && !descr->long_name ? NULL : descr;
}

/* Return type of parse_short_opt_group() and parse_long_opt() */
enum parse_orig_arg_opt_ret {
	PARSE_ORIG_ARG_OPT_RET_OK,
	PARSE_ORIG_ARG_OPT_RET_ERROR = -1,
	PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY = -2,
};

/*
 * Parses the short option group argument `short_opt_group`, starting
 * where needed depending on the state of `iter`.
 *
 * On success, sets `*item`.
 *
 * On error (except for `PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY`), sets
 * `*error`.
 */
static enum parse_orig_arg_opt_ret
parse_short_opt_group(const char *const short_opt_group,
		      const char *const next_orig_arg,
		      const struct argpar_opt_descr *const descrs,
		      struct argpar_iter *const iter,
		      struct argpar_error **const error,
		      struct argpar_item **const item)
{
	enum parse_orig_arg_opt_ret ret = PARSE_ORIG_ARG_OPT_RET_OK;
	bool used_next_orig_arg = false;
	const char *opt_arg = NULL;
	const struct argpar_opt_descr *descr;
	struct argpar_item_opt *opt_item;

	ARGPAR_ASSERT(strlen(short_opt_group) != 0);

	if (!iter->short_opt_group_ch) {
		iter->short_opt_group_ch = short_opt_group;
	}

	/* Find corresponding option descriptor */
	descr = find_descr(descrs, *iter->short_opt_group_ch, NULL);
	if (!descr) {
		const char unknown_opt_name[] = { *iter->short_opt_group_ch, '\0' };

		ret = PARSE_ORIG_ARG_OPT_RET_ERROR;

		if (set_error(error, ARGPAR_ERROR_TYPE_UNKNOWN_OPT, unknown_opt_name, NULL, true)) {
			ret = PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY;
		}

		goto error;
	}

	if (descr->with_arg) {
		if (iter->short_opt_group_ch[1]) {
			/* `-oarg` form */
			opt_arg = &iter->short_opt_group_ch[1];
		} else {
			/* `-o arg` form */
			opt_arg = next_orig_arg;
			used_next_orig_arg = true;
		}

		/*
		 * We accept `-o ''` (empty option argument), but not
		 * `-o` alone if an option argument is expected.
		 */
		if (!opt_arg || (iter->short_opt_group_ch[1] && strlen(opt_arg) == 0)) {
			ret = PARSE_ORIG_ARG_OPT_RET_ERROR;

			if (set_error(error, ARGPAR_ERROR_TYPE_MISSING_OPT_ARG, NULL, descr, true)) {
				ret = PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY;
			}

			goto error;
		}
	}

	/* Create and append option argument */
	opt_item = create_opt_item(descr, opt_arg);
	if (!opt_item) {
		ret = PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY;
		goto error;
	}

	*item = &opt_item->base;
	iter->short_opt_group_ch++;

	if (descr->with_arg || !*iter->short_opt_group_ch) {
		/* Option has an argument: no more options */
		iter->short_opt_group_ch = NULL;

		if (used_next_orig_arg) {
			iter->i += 2;
		} else {
			iter->i++;
		}
	}

	goto end;

error:
	ARGPAR_ASSERT(ret != PARSE_ORIG_ARG_OPT_RET_OK);

end:
	return ret;
}

/*
 * Parses the long option argument `long_opt_arg`.
 *
 * On success, sets `*item`.
 *
 * On error (except for `PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY`), sets
 * `*error`.
 */
static enum parse_orig_arg_opt_ret parse_long_opt(const char *const long_opt_arg,
						  const char *const next_orig_arg,
						  const struct argpar_opt_descr *const descrs,
						  struct argpar_iter *const iter,
						  struct argpar_error **const error,
						  struct argpar_item **const item)
{
	enum parse_orig_arg_opt_ret ret = PARSE_ORIG_ARG_OPT_RET_OK;
	const struct argpar_opt_descr *descr;
	struct argpar_item_opt *opt_item;
	bool used_next_orig_arg = false;

	/* Option's argument, if any */
	const char *opt_arg = NULL;

	/* Position of first `=`, if any */
	const char *eq_pos;

	/* Option name */
	const char *long_opt_name = long_opt_arg;

	ARGPAR_ASSERT(strlen(long_opt_arg) != 0);

	/* Find the first `=` in original argument */
	eq_pos = strchr(long_opt_arg, '=');
	if (eq_pos) {
		const size_t long_opt_name_size = eq_pos - long_opt_arg;

		/* Isolate the option name */
		while (long_opt_name_size > iter->tmp_buf.size - 1) {
			iter->tmp_buf.size *= 2;
			iter->tmp_buf.data =
				ARGPAR_REALLOC(iter->tmp_buf.data, char, iter->tmp_buf.size);
			if (!iter->tmp_buf.data) {
				ret = PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY;
				goto error;
			}
		}

		memcpy(iter->tmp_buf.data, long_opt_arg, long_opt_name_size);
		iter->tmp_buf.data[long_opt_name_size] = '\0';
		long_opt_name = iter->tmp_buf.data;
	}

	/* Find corresponding option descriptor */
	descr = find_descr(descrs, '\0', long_opt_name);
	if (!descr) {
		ret = PARSE_ORIG_ARG_OPT_RET_ERROR;

		if (set_error(error, ARGPAR_ERROR_TYPE_UNKNOWN_OPT, long_opt_name, NULL, false)) {
			ret = PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY;
		}

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
				ret = PARSE_ORIG_ARG_OPT_RET_ERROR;

				if (set_error(error,
					      ARGPAR_ERROR_TYPE_MISSING_OPT_ARG,
					      NULL,
					      descr,
					      false)) {
					ret = PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY;
				}

				goto error;
			}

			opt_arg = next_orig_arg;
			used_next_orig_arg = true;
		}
	} else if (eq_pos) {
		/*
		 * Unexpected `--opt=arg` style for a long option which
		 * doesn't accept an argument.
		 */
		ret = PARSE_ORIG_ARG_OPT_RET_ERROR;

		if (set_error(error, ARGPAR_ERROR_TYPE_UNEXPECTED_OPT_ARG, NULL, descr, false)) {
			ret = PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY;
		}

		goto error;
	}

	/* Create and append option argument */
	opt_item = create_opt_item(descr, opt_arg);
	if (!opt_item) {
		goto error;
	}

	if (used_next_orig_arg) {
		iter->i += 2;
	} else {
		iter->i++;
	}

	*item = &opt_item->base;
	goto end;

error:
	ARGPAR_ASSERT(ret != PARSE_ORIG_ARG_OPT_RET_OK);

end:
	return ret;
}

/*
 * Parses the original argument `orig_arg`.
 *
 * On success, sets `*item`.
 *
 * On error (except for `PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY`), sets
 * `*error`.
 */
static enum parse_orig_arg_opt_ret parse_orig_arg_opt(const char *const orig_arg,
						      const char *const next_orig_arg,
						      const struct argpar_opt_descr *const descrs,
						      struct argpar_iter *const iter,
						      struct argpar_error **const error,
						      struct argpar_item **const item)
{
	enum parse_orig_arg_opt_ret ret = PARSE_ORIG_ARG_OPT_RET_OK;

	ARGPAR_ASSERT(orig_arg[0] == '-');

	if (orig_arg[1] == '-') {
		/* Long option */
		ret = parse_long_opt(&orig_arg[2], next_orig_arg, descrs, iter, error, item);
	} else {
		/* Short option */
		ret = parse_short_opt_group(&orig_arg[1], next_orig_arg, descrs, iter, error, item);
	}

	return ret;
}

ARGPAR_HIDDEN
struct argpar_iter *argpar_iter_create(const unsigned int argc,
				       const char *const *const argv,
				       const struct argpar_opt_descr *const descrs)
{
	struct argpar_iter *iter = ARGPAR_ZALLOC(struct argpar_iter);

	if (!iter) {
		goto end;
	}

	iter->user.argc = argc;
	iter->user.argv = argv;
	iter->user.descrs = descrs;
	iter->tmp_buf.size = 128;
	iter->tmp_buf.data = ARGPAR_CALLOC(char, iter->tmp_buf.size);
	if (!iter->tmp_buf.data) {
		argpar_iter_destroy(iter);
		iter = NULL;
		goto end;
	}

end:
	return iter;
}

ARGPAR_HIDDEN
void argpar_iter_destroy(struct argpar_iter *const iter)
{
	if (iter) {
		free(iter->tmp_buf.data);
		free(iter);
	}
}

ARGPAR_HIDDEN
enum argpar_iter_next_status argpar_iter_next(struct argpar_iter *const iter,
					      const struct argpar_item **const item,
					      const struct argpar_error **const error)
{
	enum argpar_iter_next_status status;
	enum parse_orig_arg_opt_ret parse_orig_arg_opt_ret;
	const char *orig_arg;
	const char *next_orig_arg;
	struct argpar_error **const nc_error = (struct argpar_error **) error;

	ARGPAR_ASSERT(iter->i <= iter->user.argc);

	if (error) {
		*nc_error = NULL;
	}

	if (iter->i == iter->user.argc) {
		status = ARGPAR_ITER_NEXT_STATUS_END;
		goto end;
	}

	orig_arg = iter->user.argv[iter->i];
	next_orig_arg = iter->i < (iter->user.argc - 1) ? iter->user.argv[iter->i + 1] : NULL;

	if (strcmp(orig_arg, "-") == 0 || strcmp(orig_arg, "--") == 0 || orig_arg[0] != '-') {
		/* Non-option argument */
		const struct argpar_item_non_opt *const non_opt_item =
			create_non_opt_item(orig_arg, iter->i, iter->non_opt_index);

		if (!non_opt_item) {
			status = ARGPAR_ITER_NEXT_STATUS_ERROR_MEMORY;
			goto end;
		}

		iter->non_opt_index++;
		iter->i++;
		*item = &non_opt_item->base;
		status = ARGPAR_ITER_NEXT_STATUS_OK;
		goto end;
	}

	/* Option argument */
	parse_orig_arg_opt_ret = parse_orig_arg_opt(orig_arg,
						    next_orig_arg,
						    iter->user.descrs,
						    iter,
						    nc_error,
						    (struct argpar_item **) item);
	switch (parse_orig_arg_opt_ret) {
	case PARSE_ORIG_ARG_OPT_RET_OK:
		status = ARGPAR_ITER_NEXT_STATUS_OK;
		break;
	case PARSE_ORIG_ARG_OPT_RET_ERROR:
		if (error) {
			ARGPAR_ASSERT(*error);
			(*nc_error)->orig_index = iter->i;
		}
		status = ARGPAR_ITER_NEXT_STATUS_ERROR;
		break;
	case PARSE_ORIG_ARG_OPT_RET_ERROR_MEMORY:
		status = ARGPAR_ITER_NEXT_STATUS_ERROR_MEMORY;
		break;
	default:
		abort();
	}

end:
	return status;
}

ARGPAR_HIDDEN
unsigned int argpar_iter_ingested_orig_args(const struct argpar_iter *const iter)
{
	return iter->i;
}
