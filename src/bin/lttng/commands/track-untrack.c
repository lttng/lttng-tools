/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <urcu/list.h>

#include <common/mi-lttng.h>

#include "../command.h"

enum cmd_type {
	CMD_TRACK,
	CMD_UNTRACK,
};

enum tracker_type_state {
	STATE_NONE = 0,
	STATE_PID,
	STATE_VPID,
	STATE_UID,
	STATE_VUID,
	STATE_GID,
	STATE_VGID,
};

struct opt_type {
	int used;
	int all;
	char *string;
};

struct id_list {
	size_t nr;
	struct lttng_tracker_id *array;
};

static char *opt_session_name;
static int opt_kernel;
static int opt_userspace;

static struct opt_type opt_pid, opt_vpid, opt_uid, opt_vuid, opt_gid, opt_vgid;

static enum tracker_type_state type_state;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_SESSION,
	OPT_PID,
	OPT_VPID,
	OPT_UID,
	OPT_VUID,
	OPT_GID,
	OPT_VGID,
	OPT_ALL,
};

static struct poptOption long_options[] = {
	/* { longName, shortName, argInfo, argPtr, value, descrip, argDesc, } */
	{ "help",		'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0, },
	{ "session",		's', POPT_ARG_STRING, &opt_session_name, OPT_SESSION, 0, 0, },
	{ "kernel",		'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0, },
	{ "userspace",		'u', POPT_ARG_VAL, &opt_userspace, 1, 0, 0, },
	{ "pid",		'p', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_pid.string, OPT_PID, 0, 0, },
	{ "vpid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_vpid.string, OPT_VPID, 0, 0, },
	{ "uid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_uid.string, OPT_UID, 0, 0, },
	{ "vuid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_vuid.string, OPT_VUID, 0, 0, },
	{ "gid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_gid.string, OPT_GID, 0, 0, },
	{ "vgid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_vgid.string, OPT_VGID, 0, 0, },
	{ "all",		'a', POPT_ARG_NONE, 0, OPT_ALL, 0, 0, },
	{ "list-options",	0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, 0, 0, },
	{ 0, 0, 0, 0, 0, 0, 0, },
};

static struct id_list *alloc_id_list(size_t nr_items)
{
	struct id_list *id_list;
	struct lttng_tracker_id *items;

	id_list = zmalloc(sizeof(*id_list));
	if (!id_list) {
		goto error;
	}
	items = zmalloc(nr_items * sizeof(*items));
	if (!items) {
		goto error;
	}
	id_list->nr = nr_items;
	id_list->array = items;
	return id_list;
error:
	free(id_list);
	return NULL;
}

static void free_id_list(struct id_list *list)
{
	size_t nr_items;
	int i;

	if (!list) {
		return;
	}
	nr_items = list->nr;
	for (i = 0; i < nr_items; i++) {
		struct lttng_tracker_id *item = &list->array[i];

		free(item->string);
	}
	free(list);
}

static int parse_id_string(
		const char *_id_string, int all, struct id_list **_id_list)
{
	const char *one_id_str;
	char *iter;
	int retval = CMD_SUCCESS;
	int count = 0;
	struct id_list *id_list = NULL;
	char *id_string = NULL;
	char *endptr;

	if (all && _id_string) {
		ERR("An empty ID string is expected with --all");
		retval = CMD_ERROR;
		goto error;
	}
	if (!all && !_id_string) {
		ERR("An ID string is expected");
		retval = CMD_ERROR;
		goto error;
	}
	if (all) {
		/* Empty ID string means all IDs */
		id_list = alloc_id_list(1);
		if (!id_list) {
			ERR("Out of memory");
			retval = CMD_ERROR;
			goto error;
		}
		id_list->array[0].type = LTTNG_ID_ALL;
		goto assign;
	}

	id_string = strdup(_id_string);
	if (!id_string) {
		ERR("Out of memory");
		retval = CMD_ERROR;
		goto error;
	}

	/* Count */
	one_id_str = strtok_r(id_string, ",", &iter);
	while (one_id_str != NULL) {
		unsigned long v;

		if (isdigit(one_id_str[0])) {
			errno = 0;
			v = strtoul(one_id_str, &endptr, 10);
			if ((v == 0 && errno == EINVAL) ||
					(v == ULONG_MAX && errno == ERANGE) ||
					(*one_id_str != '\0' &&
							*endptr != '\0')) {
				ERR("Error parsing ID %s", one_id_str);
				retval = CMD_ERROR;
				goto error;
			}

			if ((long) v > INT_MAX || (int) v < 0) {
				ERR("Invalid ID value %ld", (long) v);
				retval = CMD_ERROR;
				goto error;
			}
		}
		count++;

		/* For next loop */
		one_id_str = strtok_r(NULL, ",", &iter);
	}
	if (count == 0) {
		ERR("Fatal error occurred when parsing pid string");
		retval = CMD_ERROR;
		goto error;
	}

	free(id_string);
	/* Identity of delimiter has been lost in first pass. */
	id_string = strdup(_id_string);
	if (!id_string) {
		ERR("Out of memory");
		retval = CMD_ERROR;
		goto error;
	}

	/* Allocate */
	id_list = alloc_id_list(count);
	if (!id_list) {
		ERR("Out of memory");
		retval = CMD_ERROR;
		goto error;
	}

	/* Reparse string and populate the id list. */
	count = 0;
	one_id_str = strtok_r(id_string, ",", &iter);
	while (one_id_str != NULL) {
		struct lttng_tracker_id *item;

		item = &id_list->array[count++];
		if (isdigit(one_id_str[0])) {
			unsigned long v;

			v = strtoul(one_id_str, NULL, 10);
			item->type = LTTNG_ID_VALUE;
			item->value = (int) v;
		} else {
			item->type = LTTNG_ID_STRING;
			item->string = strdup(one_id_str);
			if (!item->string) {
				PERROR("Failed to allocate ID string");
				retval = CMD_ERROR;
				goto error;
			}
		}

		/* For next loop */
		one_id_str = strtok_r(NULL, ",", &iter);
	}

assign:
	*_id_list = id_list;
	goto end;	/* SUCCESS */

	/* ERROR */
error:
	free_id_list(id_list);
end:
	free(id_string);
	return retval;
}

static const char *get_tracker_str(enum lttng_tracker_type tracker_type)
{
	switch (tracker_type) {
	case LTTNG_TRACKER_PID:
		return "PID";
	case LTTNG_TRACKER_VPID:
		return "VPID";
	case LTTNG_TRACKER_UID:
		return "UID";
	case LTTNG_TRACKER_VUID:
		return "VUID";
	case LTTNG_TRACKER_GID:
		return "GID";
	case LTTNG_TRACKER_VGID:
		return "VGID";
	default:
		return NULL;
	}
	return NULL;
}

static enum cmd_error_code track_untrack_id(enum cmd_type cmd_type,
		const char *cmd_str,
		const char *session_name,
		const char *id_string,
		int all,
		struct mi_writer *writer,
		enum lttng_tracker_type tracker_type)
{
	int ret, success = 1 , i;
	enum cmd_error_code retval = CMD_SUCCESS;
	struct id_list *id_list = NULL;
	struct lttng_domain dom;
	struct lttng_handle *handle = NULL;
	int (*cmd_func)(struct lttng_handle *handle,
			enum lttng_tracker_type tracker_type,
			const struct lttng_tracker_id *id);
	const char *tracker_str;

	switch (cmd_type) {
	case CMD_TRACK:
		cmd_func = lttng_track_id;
		break;
	case CMD_UNTRACK:
		cmd_func = lttng_untrack_id;
		break;
	default:
		ERR("Unknown command");
		retval = CMD_ERROR;
		goto end;
	}
	memset(&dom, 0, sizeof(dom));
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
		if (tracker_type == LTTNG_TRACKER_PID) {
			tracker_type = LTTNG_TRACKER_VPID;
		}
	} else {
		/* Checked by the caller. */
		assert(0);
	}
	tracker_str = get_tracker_str(tracker_type);
	if (!tracker_str) {
		ERR("Unknown tracker type");
		retval = CMD_ERROR;
		goto end;
	}
	ret = parse_id_string(id_string, all, &id_list);
	if (ret != CMD_SUCCESS) {
		ERR("Error parsing %s string", tracker_str);
		retval = CMD_ERROR;
		goto end;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		retval = CMD_ERROR;
		goto end;
	}

	if (writer) {
		/* Open tracker_id and targets elements */
		ret = mi_lttng_id_tracker_open(writer, tracker_type);
		if (ret) {
			goto end;
		}
	}

	for (i = 0; i < id_list->nr; i++) {
		struct lttng_tracker_id *item = &id_list->array[i];

		switch (item->type) {
		case LTTNG_ID_ALL:
			DBG("%s all IDs", cmd_str);
			break;
		case LTTNG_ID_VALUE:
			DBG("%s ID %d", cmd_str, item->value);
			break;
		case LTTNG_ID_STRING:
			DBG("%s ID '%s'", cmd_str, item->string);
			break;
		default:
			retval = CMD_ERROR;
			goto end;
		}
		ret = cmd_func(handle, tracker_type, item);
		if (ret) {
			char *msg = NULL;

			switch (-ret) {
			case LTTNG_ERR_ID_TRACKED:
				msg = "already tracked";
				success = 1;
				retval = CMD_SUCCESS;
				break;
			case LTTNG_ERR_ID_NOT_TRACKED:
				msg = "already not tracked";
				success = 1;
				retval = CMD_SUCCESS;
				break;
			default:
				ERR("%s", lttng_strerror(ret));
				success = 0;
				retval = CMD_ERROR;
				break;
			}
			if (msg) {
				switch (item->type) {
				case LTTNG_ID_ALL:
					WARN("All %ss %s in session %s",
							tracker_str, msg,
							session_name);
					break;
				case LTTNG_ID_VALUE:
					WARN("%s %i %s in session %s",
							tracker_str,
							item->value, msg,
							session_name);
					break;
				case LTTNG_ID_STRING:
					WARN("%s '%s' %s in session %s",
							tracker_str,
							item->string, msg,
							session_name);
					break;
				default:
					retval = CMD_ERROR;
					goto end;
				}
			}
		} else {
			switch (item->type) {
			case LTTNG_ID_ALL:
				MSG("All %ss %sed in session %s", tracker_str,
						cmd_str, session_name);
				break;
			case LTTNG_ID_VALUE:
				MSG("%s %i %sed in session %s", tracker_str,
						item->value, cmd_str,
						session_name);
				break;
			case LTTNG_ID_STRING:
				MSG("%s '%s' %sed in session %s", tracker_str,
						item->string, cmd_str,
						session_name);
				break;
			default:
				retval = CMD_ERROR;
				goto end;
			}
			success = 1;
		}

		/* Mi */
		if (writer) {
			ret = mi_lttng_id_target(writer, tracker_type, item, 1);
			if (ret) {
				retval = CMD_ERROR;
				goto end;
			}

			ret = mi_lttng_writer_write_element_bool(writer,
					mi_lttng_element_success, success);
			if (ret) {
				retval = CMD_ERROR;
				goto end;
			}

			ret = mi_lttng_writer_close_element(writer);
			if (ret) {
				retval = CMD_ERROR;
				goto end;
			}
		}
	}

	if (writer) {
		/* Close targets and tracker_id elements */
		ret = mi_lttng_close_multi_element(writer, 2);
		if (ret) {
			retval = CMD_ERROR;
			goto end;
		}
	}

end:
	if (handle) {
		lttng_destroy_handle(handle);
	}
	free_id_list(id_list);
	return retval;
}

static
const char *get_mi_element_command(enum cmd_type cmd_type)
{
	switch (cmd_type) {
	case CMD_TRACK:
		return mi_lttng_element_command_track;
	case CMD_UNTRACK:
		return mi_lttng_element_command_untrack;
	default:
		return NULL;
	}
}

static void print_err_duplicate(const char *type)
{
	ERR("The --%s option can only be used once. A list of comma-separated values can be specified.",
			type);
}

/*
 * Add/remove tracker to/from session.
 */
static
int cmd_track_untrack(enum cmd_type cmd_type, const char *cmd_str,
		int argc, const char **argv, const char *help_msg)
{
	int opt, ret = 0;
	enum cmd_error_code command_ret = CMD_SUCCESS;
	int success = 1;
	static poptContext pc;
	char *session_name = NULL;
	struct mi_writer *writer = NULL;

	if (argc < 1) {
		command_ret = CMD_ERROR;
		goto end;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		case OPT_SESSION:
			break;
		case OPT_PID:
			if (opt_pid.used) {
				print_err_duplicate("pid");
				command_ret = CMD_ERROR;
				goto end;
			}
			opt_pid.used = 1;
			type_state = STATE_PID;
			break;
		case OPT_VPID:
			if (opt_vpid.used) {
				print_err_duplicate("vpid");
				command_ret = CMD_ERROR;
				goto end;
			}
			opt_vpid.used = 1;
			type_state = STATE_VPID;
			break;
		case OPT_UID:
			if (opt_uid.used) {
				print_err_duplicate("uid");
				command_ret = CMD_ERROR;
				goto end;
			}
			opt_uid.used = 1;
			type_state = STATE_UID;
			break;
		case OPT_VUID:
			if (opt_vuid.used) {
				print_err_duplicate("vuid");
				command_ret = CMD_ERROR;
				goto end;
			}
			opt_vuid.used = 1;
			type_state = STATE_VUID;
			break;
		case OPT_GID:
			if (opt_gid.used) {
				print_err_duplicate("gid");
				command_ret = CMD_ERROR;
				goto end;
			}
			opt_gid.used = 1;
			type_state = STATE_GID;
			break;
		case OPT_VGID:
			if (opt_vgid.used) {
				print_err_duplicate("vgid");
				command_ret = CMD_ERROR;
				goto end;
			}
			opt_vgid.used = 1;
			type_state = STATE_VGID;
			break;
		case OPT_ALL:
			switch (type_state) {
			case STATE_PID:
				opt_pid.all = 1;
				break;
			case STATE_VPID:
				opt_vpid.all = 1;
				break;
			case STATE_UID:
				opt_uid.all = 1;
				break;
			case STATE_VUID:
				opt_vuid.all = 1;
				break;
			case STATE_GID:
				opt_gid.all = 1;
				break;
			case STATE_VGID:
				opt_vgid.all = 1;
				break;
			default:
				command_ret = CMD_ERROR;
				goto end;
			}
			break;
		default:
			command_ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = print_missing_or_multiple_domains(opt_kernel + opt_userspace);
	if (ret) {
		command_ret = CMD_ERROR;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			command_ret = CMD_ERROR;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			command_ret = CMD_ERROR;
			goto end;
		}
	}

	if (writer) {
		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				get_mi_element_command(cmd_type));
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}

		ret = mi_lttng_trackers_open(writer);
		if (ret) {
			goto end;
		}
	}

	if (opt_pid.used) {
		command_ret = track_untrack_id(cmd_type, cmd_str, session_name,
				opt_pid.string, opt_pid.all, writer,
				LTTNG_TRACKER_PID);
		if (command_ret != CMD_SUCCESS) {
			success = 0;
		}
	}
	if (opt_vpid.used) {
		command_ret = track_untrack_id(cmd_type, cmd_str, session_name,
				opt_vpid.string, opt_vpid.all, writer,
				LTTNG_TRACKER_VPID);
		if (command_ret != CMD_SUCCESS) {
			success = 0;
		}
	}
	if (opt_uid.used) {
		command_ret = track_untrack_id(cmd_type, cmd_str, session_name,
				opt_uid.string, opt_uid.all, writer,
				LTTNG_TRACKER_UID);
		if (command_ret != CMD_SUCCESS) {
			success = 0;
		}
	}
	if (opt_vuid.used) {
		command_ret = track_untrack_id(cmd_type, cmd_str, session_name,
				opt_vuid.string, opt_vuid.all, writer,
				LTTNG_TRACKER_VUID);
		if (command_ret != CMD_SUCCESS) {
			success = 0;
		}
	}
	if (opt_gid.used) {
		command_ret = track_untrack_id(cmd_type, cmd_str, session_name,
				opt_gid.string, opt_gid.all, writer,
				LTTNG_TRACKER_GID);
		if (command_ret != CMD_SUCCESS) {
			success = 0;
		}
	}
	if (opt_vgid.used) {
		command_ret = track_untrack_id(cmd_type, cmd_str, session_name,
				opt_vgid.string, opt_vgid.all, writer,
				LTTNG_TRACKER_VGID);
		if (command_ret != CMD_SUCCESS) {
			success = 0;
		}
	}

	/* Mi closing */
	if (writer) {
		/* Close trackers and output elements */
		ret = mi_lttng_close_multi_element(writer, 2);
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success, success);
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}
	}

end:
	if (!opt_session_name) {
		free(session_name);
	}

	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		command_ret = CMD_ERROR;
	}

	poptFreeContext(pc);
	return (int) command_ret;
}

int cmd_track(int argc, const char **argv)
{
	static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-track.1.h>
#else
	NULL
#endif
	;

	return cmd_track_untrack(CMD_TRACK, "track", argc, argv, help_msg);
}

int cmd_untrack(int argc, const char **argv)
{
	static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-untrack.1.h>
#else
	NULL
#endif
	;

	return cmd_track_untrack(CMD_UNTRACK, "untrack", argc, argv, help_msg);
}
