/*
 * Copyright (C) 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "../command.h"
#include "common/argpar/argpar.h"
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

static const
struct argpar_opt_descr remove_trigger_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_LIST_OPTIONS, '\0', "list-options", false },
	{ OPT_OWNER_UID, '\0', "owner-uid", true },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static
bool assign_string(char **dest, const char *src, const char *opt_name)
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
	int ret;
	struct argpar_parse_ret argpar_parse_ret = {};
	const char *name = NULL;
	int i;
	struct lttng_triggers *triggers = NULL;
	unsigned int triggers_count;
	enum lttng_trigger_status trigger_status;
	const struct lttng_trigger *trigger_to_remove = NULL;
	char *owner_uid = NULL;
	long long uid;

	argpar_parse_ret = argpar_parse(argc - 1, argv + 1,
		remove_trigger_options, true);
	if (!argpar_parse_ret.items) {
		ERR("%s", argpar_parse_ret.error);
		goto error;
	}

	for (i = 0; i < argpar_parse_ret.items->n_items; i++) {
		const struct argpar_item *item =
				argpar_parse_ret.items->items[i];

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_item_opt *item_opt =
					(const struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_HELP:
				SHOW_HELP();
				ret = 0;
				goto end;
			case OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout,
					remove_trigger_options);
				ret = 0;
				goto end;
			case OPT_OWNER_UID:
			{
				if (!assign_string(&owner_uid, item_opt->arg,
						"--owner-uid")) {
					goto error;
				}
				break;
			}
			default:
				abort();
			}
		} else {
			const struct argpar_item_non_opt *item_non_opt =
					(const struct argpar_item_non_opt *) item;

			if (name) {
				ERR("Unexpected argument '%s'", item_non_opt->arg);
				goto error;
			}

			name = item_non_opt->arg;
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
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

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

		trigger_status = lttng_trigger_get_owner_uid(
				trigger, &trigger_uid);
		assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

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

	MSG("Removed trigger `%s`.", name);

	ret = 0;
	goto end;

error:
	ret = 1;

end:
	argpar_parse_ret_fini(&argpar_parse_ret);
	lttng_triggers_destroy(triggers);
	free(owner_uid);

	return ret;
}
