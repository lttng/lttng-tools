/*
 * SPDX-FileCopyrightText: 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "../command.hpp"
#include "common/argpar-utils/argpar-utils.hpp"
#include "common/mi-lttng.hpp"
#include "vendor/argpar/argpar.h"

#include <lttng/lttng.h>

#include <stdio.h>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-remove-trigger.1.h>
	;
#endif

enum {
	OPT_HELP,
	OPT_LIST_OPTIONS,
	OPT_OWNER_UID,
};

static const struct argpar_opt_descr remove_trigger_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_LIST_OPTIONS, '\0', "list-options", false },
	{ OPT_OWNER_UID, '\0', "owner-uid", true },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static bool assign_string(char **dest, const char *src, const char *opt_name)
{
	bool ret;

	if (*dest) {
		ERR("Duplicate option '%s' given.", opt_name);
		goto error;
	}

	*dest = strdup(src);
	if (!*dest) {
		ERR("Failed to allocate '%s' string.", opt_name);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

int cmd_remove_trigger(int argc, const char **argv)
{
	enum lttng_error_code ret_code;
	int ret;
	struct argpar_iter *argpar_iter = nullptr;
	const struct argpar_item *argpar_item = nullptr;
	const char *name = nullptr;
	int i;
	struct lttng_triggers *triggers = nullptr;
	unsigned int triggers_count;
	enum lttng_trigger_status trigger_status;
	const struct lttng_trigger *trigger_to_remove = nullptr;
	char *owner_uid = nullptr;
	long long uid;
	struct mi_writer *mi_writer = nullptr;
	const char **args;

	if (lttng_opt_mi) {
		mi_writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!mi_writer) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Open command element. */
		ret = mi_lttng_writer_command_open(mi_writer,
						   mi_lttng_element_command_remove_trigger);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Open output element. */
		ret = mi_lttng_writer_open_element(mi_writer, mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	args = argv + 1;

	argpar_iter = argpar_iter_create(argc - 1, args, remove_trigger_options);
	if (!argpar_iter) {
		ERR("Failed to allocate an argpar iter.");
		goto error;
	}

	while (true) {
		enum parse_next_item_status status;

		status =
			parse_next_item(argpar_iter, &argpar_item, 1, args, true, nullptr, nullptr);
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR ||
		    status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			goto error;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		assert(status == PARSE_NEXT_ITEM_STATUS_OK);

		if (argpar_item_type(argpar_item) == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_opt_descr *descr = argpar_item_opt_descr(argpar_item);
			const char *arg = argpar_item_opt_arg(argpar_item);

			switch (descr->id) {
			case OPT_HELP:
				SHOW_HELP();
				ret = 0;
				goto end;
			case OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout, remove_trigger_options);
				ret = 0;
				goto end;
			case OPT_OWNER_UID:
			{
				if (!assign_string(&owner_uid, arg, "--owner-uid")) {
					goto error;
				}
				break;
			}
			default:
				abort();
			}
		} else {
			const char *arg = argpar_item_non_opt_arg(argpar_item);

			if (name) {
				ERR("Unexpected argument '%s'", arg);
				goto error;
			}

			name = arg;
		}
	}

	if (!name) {
		ERR("Missing `name` argument.");
		goto error;
	}

	if (owner_uid) {
		char *end;

		errno = 0;
		uid = strtol(owner_uid, &end, 10);
		if (end == owner_uid || *end != '\0' || errno != 0) {
			ERR("Failed to parse `%s` as an integer.", owner_uid);
		}
	} else {
		uid = geteuid();
	}

	ret = lttng_list_triggers(&triggers);
	if (ret != LTTNG_OK) {
		ERR("Failed to get the list of triggers.");
		goto error;
	}

	trigger_status = lttng_triggers_get_count(triggers, &triggers_count);
	LTTNG_ASSERT(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	for (i = 0; i < triggers_count; i++) {
		const struct lttng_trigger *trigger;
		const char *trigger_name;
		uid_t trigger_uid;

		trigger = lttng_triggers_get_at_index(triggers, i);
		trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
		switch (trigger_status) {
		case LTTNG_TRIGGER_STATUS_OK:
			break;
		case LTTNG_TRIGGER_STATUS_UNSET:
			/* Don't compare against anonymous triggers. */
			continue;
		default:
			abort();
		}

		trigger_status = lttng_trigger_get_owner_uid(trigger, &trigger_uid);
		LTTNG_ASSERT(trigger_status == LTTNG_TRIGGER_STATUS_OK);

		if (trigger_uid == uid && strcmp(trigger_name, name) == 0) {
			trigger_to_remove = trigger;
			break;
		}
	}

	if (!trigger_to_remove) {
		ERR("Couldn't find trigger with name `%s`.", name);
		goto error;
	}

	ret = lttng_unregister_trigger(trigger_to_remove);
	if (ret != 0) {
		ERR("Failed to unregister trigger `%s`.", name);
		goto error;
	}

	if (lttng_opt_mi) {
		ret_code = lttng_trigger_mi_serialize(trigger_to_remove, mi_writer, nullptr);
		if (ret_code != LTTNG_OK) {
			goto error;
		}
	}
	MSG("Removed trigger `%s`.", name);

	ret = 0;
	goto end;

error:
	ret = 1;

end:
	/* Mi closing. */
	if (lttng_opt_mi && mi_writer) {
		/* Close output element. */
		int mi_ret = mi_lttng_writer_close_element(mi_writer);
		if (mi_ret) {
			ret = 1;
			goto cleanup;
		}

		mi_ret = mi_lttng_writer_write_element_bool(
			mi_writer, mi_lttng_element_command_success, ret ? 0 : 1);
		if (mi_ret) {
			ret = 1;
			goto cleanup;
		}

		/* Command element close. */
		mi_ret = mi_lttng_writer_command_close(mi_writer);
		if (mi_ret) {
			ret = 1;
			goto cleanup;
		}
	}

cleanup:
	argpar_item_destroy(argpar_item);
	argpar_iter_destroy(argpar_iter);
	lttng_triggers_destroy(triggers);
	free(owner_uid);

	if (mi_writer && mi_lttng_writer_destroy(mi_writer)) {
		/* Preserve original error code. */
		ret = ret ? ret : CMD_ERROR;
	}
	return ret;
}
