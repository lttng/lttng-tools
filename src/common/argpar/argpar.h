/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_ARGPAR_H
#define BABELTRACE_ARGPAR_H

#include <stdbool.h>

/*
 * argpar is a library that provides facilities for argument parsing.
 *
 * Two APIs are available:
 *
 *   - The iterator-style API, where you initialize a state object with
 *     `argpar_state_create`, then repeatedly call `argpar_state_parse_next` to
 *     get the arguments, until (1) there are no more arguments, (2) the parser
 *     encounters an error (e.g. unknown option) or (3) you get bored.  This
 *     API gives you more control on when to stop parsing the arguments.
 *
 *   - The parse-everything-in-one-shot-API, where you call `argpar_parse`,
 *     which parses the arguments until (1) there are not more arguments or
 *     (2) it encounters a parser error.  It returns you a list of all the
 *     arguments it was able to parse, which you can consult at your leisure.
 *
 * The following describes how arguments are parsed, and applies to both APIs.
 *
 * argpar parses the arguments `argv` of which the count is `argc` using the
 * sentinel-terminated (use `ARGPAR_OPT_DESCR_SENTINEL`) option
 * descriptor array `descrs`.
 *
 * argpar considers ALL the elements of `argv`, including the* first one, so
 * that you would typically pass `argc - 1` and `&argv[1]` from what main()
 * receives.
 *
 * This argument parser supports:
 *
 * * Short options without an argument, possibly tied together:
 *
 *       -f -auf -n
 *
 * * Short options with argument:
 *
 *       -b 45 -f/mein/file -xyzhello
 *
 * * Long options without an argument:
 *
 *       --five-guys --burger-king --pizza-hut --subway
 *
 * * Long options with arguments:
 *
 *       --security enable --time=18.56
 *
 * * Non-option arguments (anything else).
 *
 * This parser does not accept `-` or `--` as arguments. The latter
 * means "end of options" for many command-line tools, but this function
 * is all about keeping the order of the arguments, so it does not mean
 * much to put them at the end. This has the side effect that a
 * non-option argument cannot have the form of an option, for example if
 * you need to pass the exact relative path `--component`. In that case,
 * you would need to pass `./--component`. There's no generic way to
 * escape `-` for the moment.
 *
 * This parser accepts duplicate options (it will output one item for each
 * instance).
 *
 * The returned items are of the type `struct argpar_item *`.  Each item
 * is to be casted to the appropriate type (`struct argpar_item_opt *` or
 * `struct argpar_item_non_opt *`) depending on its type.
 *
 * The items are returned in the same order that the arguments were parsed,
 * including non-option arguments. This means, for example, that for
 *
 *     --hello --meow=23 /path/to/file -b
 *
 * found items are returned in this order: option item (--hello), option item
 * (--meow=23), non-option item (/path/to/file) and option item (-b).
 */

/* Sentinel for an option descriptor array */
#define ARGPAR_OPT_DESCR_SENTINEL	{ -1, '\0', NULL, false }

/*
 * ARGPAR_HIDDEN: if argpar is used in some shared library, we don't want them
 * to be exported by that library, so mark them as "hidden".
 *
 * On Windows, symbols are local unless explicitly exported,
 * see https://gcc.gnu.org/wiki/Visibility
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#define ARGPAR_HIDDEN
#else
#define ARGPAR_HIDDEN __attribute__((visibility("hidden")))
#endif

/* Forward-declaration for the opaque type. */
struct argpar_state;

/* Option descriptor */
struct argpar_opt_descr {
	/* Numeric ID for this option */
	const int id;

	/* Short option character, or `\0` */
	const char short_name;

	/* Long option name (without `--`), or `NULL` */
	const char * const long_name;

	/* True if this option has an argument */
	const bool with_arg;
};

/* Item type */
enum argpar_item_type {
	/* Option */
	ARGPAR_ITEM_TYPE_OPT,

	/* Non-option */
	ARGPAR_ITEM_TYPE_NON_OPT,
};

/* Base item */
struct argpar_item {
	enum argpar_item_type type;
};

/* Option item */
struct argpar_item_opt {
	struct argpar_item base;

	/* Corresponding descriptor */
	const struct argpar_opt_descr *descr;

	/* Argument, or `NULL` if none */
	const char *arg;
};

/* Non-option item */
struct argpar_item_non_opt {
	struct argpar_item base;

	/*
	 * Complete argument, pointing to one of the entries of the
	 * original arguments (`argv`).
	 */
	const char *arg;

	/* Index of this argument amongst all original arguments (`argv`) */
	unsigned int orig_index;

	/* Index of this argument amongst other non-option arguments */
	unsigned int non_opt_index;
};

struct argpar_item_array {
	/* Array of `struct argpar_item *`, or `NULL` on error */
	struct argpar_item **items;

	/* Number of used slots in `items`. */
	unsigned int n_items;

	/* Number of allocated slots in `items`. */
	unsigned int n_alloc;
};

/* What is returned by argpar_parse() */
struct argpar_parse_ret {
	/* Array of `struct argpar_item *`, or `NULL` on error */
	struct argpar_item_array *items;

	/* Error string, or `NULL` if none */
	char *error;

	/* Number of original arguments (`argv`) ingested */
	unsigned int ingested_orig_args;
};

/*
 * Parses arguments in `argv` until the end is reached or an error is
 * encountered.
 *
 * On success, this function returns an array of items
 * (field `items` of `struct argpar_parse_ret`) corresponding to each parsed
 * argument.
 *
 * In the returned structure, `ingested_orig_args` is the number of
 * ingested arguments within `argv` to produce the resulting array of
 * items.
 *
 * If `fail_on_unknown_opt` is true, then on success `ingested_orig_args` is
 * equal to `argc`. Otherwise, `ingested_orig_args` contains the number of
 * original arguments until an unknown _option_ occurs. For example, with
 *
 *     --great --white contact nuance --shark nuclear
 *
 * if `--shark` is not described within `descrs` and
 * `fail_on_unknown_opt` is false, then `ingested_orig_args` is 4 (two
 * options, two non-options), whereas `argc` is 6.
 *
 * This makes it possible to know where a command name is, for example.
 * With those arguments:
 *
 *     --verbose --stuff=23 do-something --specific-opt -f -b
 *
 * and the descriptors for `--verbose` and `--stuff` only, the function
 * returns the `--verbose` and `--stuff` option items, the
 * `do-something` non-option item, and that three original arguments
 * were ingested. This means you can start the next argument parsing
 * stage, with option descriptors depending on the command name, at
 * `&argv[3]`.
 *
 * Note that `ingested_orig_args` is not always equal to the number of
 * returned items, as
 *
 *     --hello -fdw
 *
 * for example contains two ingested original arguments, but four
 * resulting items.
 *
 * On failure, the returned structure's `items` member is `NULL`, and
 * the `error` string member contains details about the error.
 *
 * You can finalize the returned structure with
 * argpar_parse_ret_fini().
 */
ARGPAR_HIDDEN
struct argpar_parse_ret argpar_parse(unsigned int argc,
		const char * const *argv,
		const struct argpar_opt_descr *descrs,
		bool fail_on_unknown_opt);

/*
 * Finalizes what is returned by argpar_parse().
 *
 * It is safe to call argpar_parse() multiple times with the same
 * structure.
 */
ARGPAR_HIDDEN
void argpar_parse_ret_fini(struct argpar_parse_ret *ret);

/*
 * Creates an instance of `struct argpar_state`.
 *
 * This sets up the argpar_state structure, but does not actually
 * start parsing the arguments.
 *
 * When you are done with it, the state must be freed with
 * `argpar_state_destroy`.
 */
ARGPAR_HIDDEN
struct argpar_state *argpar_state_create(
		unsigned int argc,
		const char * const *argv,
		const struct argpar_opt_descr * const descrs);

/*
 * Destroys an instance of `struct argpar_state`.
 */
ARGPAR_HIDDEN
void argpar_state_destroy(struct argpar_state *state);


enum argpar_state_parse_next_status {
	ARGPAR_STATE_PARSE_NEXT_STATUS_OK,
	ARGPAR_STATE_PARSE_NEXT_STATUS_END,
	ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT,
	ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR,
};

/*
 * Parses and returns the next argument from `state`.
 *
 * On success, an item describing the argument is returned in `*item` and
 * ARGPAR_STATE_PARSE_NEXT_STATUS_OK is returned.  The item must be freed with
 * `argpar_item_destroy`.
 *
 * If there are no more arguments to parse, ARGPAR_STATE_PARSE_NEXT_STATUS_END
 * is returned.
 *
 * On failure (status codes ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT and
 * ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR), an error string is returned in `*error`.
 * This string must be freed with `free`.
 */
enum argpar_state_parse_next_status argpar_state_parse_next(
		struct argpar_state *state,
		struct argpar_item **item,
		char **error);

/*
 * Return the number of ingested elements from argv that were required to
 * produce the previously returned items.
 */
ARGPAR_HIDDEN
int argpar_state_get_ingested_orig_args(struct argpar_state *state);

/*
 * Destroy an instance of `struct argpar_item`, as returned by
 * argpar_state_parse_next.
 */
ARGPAR_HIDDEN
void argpar_item_destroy(struct argpar_item *item);

#define ARGPAR_ITEM_DESTROY_AND_RESET(_item)	\
	{					\
		argpar_item_destroy(_item);	\
		_item = NULL;			\
	}


#endif /* BABELTRACE_ARGPAR_H */
