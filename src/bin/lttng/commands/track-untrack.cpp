/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <ctype.h>
#include <popt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <urcu/list.h>

#include <common/dynamic-array.hpp>
#include <common/mi-lttng.hpp>
#include <common/optional.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/tracker.hpp>

#include <lttng/lttng.h>

#include "../command.hpp"

namespace {
struct process_attr_command_args {
	enum lttng_process_attr process_attr;
	/* Present in the user's command. */
	bool requested;
	bool all;
	struct lttng_dynamic_pointer_array string_args;
};
} /* namespace */

enum cmd_type {
	CMD_TRACK,
	CMD_UNTRACK,
};

/* Offset OPT_ values by one since libpopt gives '0' a special meaning. */
enum {
	OPT_PID = LTTNG_PROCESS_ATTR_PROCESS_ID + 1,
	OPT_VPID = LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID + 1,
	OPT_UID = LTTNG_PROCESS_ATTR_USER_ID + 1,
	OPT_VUID = LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID + 1,
	OPT_GID = LTTNG_PROCESS_ATTR_GROUP_ID + 1,
	OPT_VGID = LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID + 1,
	OPT_HELP,
	OPT_LIST_OPTIONS,
	OPT_SESSION,
	OPT_ALL,
};

static char *opt_session_name;
static int opt_kernel;
static int opt_userspace;
static char *opt_str_arg;

static struct poptOption long_options[] = {
	/* { longName, shortName, argInfo, argPtr, value, descrip, argDesc, } */
	{ "help",		'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0, },
	{ "session",		's', POPT_ARG_STRING, &opt_session_name, OPT_SESSION, 0, 0, },
	{ "kernel",		'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0, },
	{ "userspace",		'u', POPT_ARG_VAL, &opt_userspace, 1, 0, 0, },
	{ "pid",		'p', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_str_arg, OPT_PID, 0, 0, },
	{ "vpid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_str_arg, OPT_VPID, 0, 0, },
	{ "uid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_str_arg, OPT_UID, 0, 0, },
	{ "vuid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_str_arg, OPT_VUID, 0, 0, },
	{ "gid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_str_arg, OPT_GID, 0, 0, },
	{ "vgid",		0, POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_str_arg, OPT_VGID, 0, 0, },
	{ "all",		'a', POPT_ARG_NONE, 0, OPT_ALL, 0, 0, },
	{ "list-options",	0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, 0, 0, },
	{ 0, 0, 0, 0, 0, 0, 0, },
};

static struct process_attr_command_args
		process_attr_commands[LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID + 1];

static void process_attr_command_init(struct process_attr_command_args *cmd,
		enum lttng_process_attr process_attr)
{
	cmd->process_attr = process_attr;
	cmd->all = false;
	lttng_dynamic_pointer_array_init(&cmd->string_args, free);
}

static void process_attr_command_fini(struct process_attr_command_args *cmd)
{
	lttng_dynamic_pointer_array_reset(&cmd->string_args);
}

static const char *get_capitalized_process_attr_str(enum lttng_process_attr process_attr)
{
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
		return "Process ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		return "Virtual process ID";
	case LTTNG_PROCESS_ATTR_USER_ID:
		return "User ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		return "Virtual user ID";
	case LTTNG_PROCESS_ATTR_GROUP_ID:
		return "Group ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		return "Virtual group ID";
	default:
		return "Unknown";
	}
	return NULL;
}

static bool ust_process_attr_supported(enum lttng_process_attr *process_attr)
{
	bool supported;

	switch (*process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
		*process_attr = LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID;
		/* fall-through. */
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		supported = true;
		break;
	default:
		ERR("The %s process attribute cannot be tracked in the user space domain.",
				lttng_process_attr_to_string(*process_attr));
		supported = false;
		break;
	}
	return supported;
}

static const char *get_mi_element_command(enum cmd_type cmd_type)
{
	switch (cmd_type) {
	case CMD_TRACK:
		return mi_lttng_element_command_track;
	case CMD_UNTRACK:
		return mi_lttng_element_command_untrack;
	default:
		abort();
	}
}

static enum cmd_error_code run_command_all(enum cmd_type cmd_type,
		const char *session_name,
		enum lttng_domain_type domain_type,
		enum lttng_process_attr process_attr,
		struct mi_writer *writer)
{
	struct lttng_process_attr_tracker_handle *tracker_handle = NULL;
	const enum lttng_error_code handle_ret_code =
			lttng_session_get_tracker_handle(session_name,
					domain_type, process_attr,
					&tracker_handle);
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	enum lttng_process_attr_tracker_handle_status status;

	if (writer) {
		const int ret = mi_lttng_all_process_attribute_value(
				writer, process_attr, true);
		if (ret) {
			cmd_ret = CMD_FATAL;
			goto end;
		}
	}

	if (handle_ret_code != LTTNG_OK) {
		ERR("Session `%s` does not exist", session_name);
		cmd_ret = CMD_FATAL;
		goto end;
	}

	status = lttng_process_attr_tracker_handle_set_tracking_policy(
			tracker_handle,
			cmd_type == CMD_TRACK ?
					LTTNG_TRACKING_POLICY_INCLUDE_ALL :
					LTTNG_TRACKING_POLICY_EXCLUDE_ALL);
	switch (status) {
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK:
		if (cmd_type == CMD_TRACK) {
			MSG("%s tracking policy set to `include all`",
					get_capitalized_process_attr_str(process_attr));
		} else {
			MSG("%s tracking policy set to `exclude all`",
					get_capitalized_process_attr_str(process_attr));
		}
		break;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST:
		ERR("%s", lttng_strerror(-LTTNG_ERR_SESS_NOT_FOUND));
		break;
	default:
		ERR("Unknown error encountered while setting tracking policy of %s tracker to `%s`",
				lttng_process_attr_to_string(process_attr),
				cmd_type == CMD_TRACK ? "include all" :
							"exclude all");
		cmd_ret = CMD_FATAL;
		break;
	}
end:
	if (writer) {
		int ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_success,
				cmd_ret == CMD_SUCCESS);

		if (ret) {
			cmd_ret = CMD_FATAL;
		} else {
			ret = mi_lttng_writer_close_element(writer);
			cmd_ret = ret == 0 ? cmd_ret : CMD_FATAL;
		}
	}
	lttng_process_attr_tracker_handle_destroy(tracker_handle);
	return cmd_ret;
}

static enum cmd_error_code run_command_string(enum cmd_type cmd_type,
		const char *session_name,
		enum lttng_domain_type domain_type,
		enum lttng_process_attr process_attr,
		const char *_args,
		struct mi_writer *writer)
{
	struct lttng_process_attr_tracker_handle *tracker_handle = NULL;
	const enum lttng_error_code handle_ret_code =
			lttng_session_get_tracker_handle(session_name,
					domain_type, process_attr,
					&tracker_handle);
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	const char *one_value_str;
	char *args = strdup(_args);
	char *iter = args;
	bool policy_set = false;

	if (!args) {
		ERR("%s", lttng_strerror(-LTTNG_ERR_NOMEM));
		cmd_ret = CMD_FATAL;
		goto end;
	}

	if (handle_ret_code != LTTNG_OK) {
		ERR("%s", lttng_strerror(-handle_ret_code));
		cmd_ret = CMD_FATAL;
		goto end;
	}

	while ((one_value_str = strtok_r(iter, ",", &iter)) != NULL) {
		const bool is_numerical_argument = isdigit(one_value_str[0]);
		enum lttng_process_attr_tracker_handle_status status;
		enum lttng_tracking_policy policy;
		int ret;
		char *prettified_arg;

		if (!policy_set) {
			status = lttng_process_attr_tracker_handle_get_tracking_policy(
					tracker_handle, &policy);
			if (status != LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
				break;
			}

			if (policy != LTTNG_TRACKING_POLICY_INCLUDE_SET) {
				status = lttng_process_attr_tracker_handle_set_tracking_policy(
						tracker_handle,
						LTTNG_TRACKING_POLICY_INCLUDE_SET);
				if (status != LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
					break;
				}
			}
			policy_set = true;
		}

		if (is_numerical_argument) {
			const unsigned long one_value_int =
					strtoul(one_value_str, NULL, 10);

			if (writer) {
				ret = mi_lttng_integral_process_attribute_value(
						writer, process_attr,
						(int64_t) one_value_int, true);
				if (ret) {
					cmd_ret = CMD_FATAL;
					goto end;
				}
			}

			switch (process_attr) {
			case LTTNG_PROCESS_ATTR_PROCESS_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_process_id_tracker_handle_add_pid(
									 tracker_handle,
									 (pid_t) one_value_int) :
							 lttng_process_attr_process_id_tracker_handle_remove_pid(
									 tracker_handle,
									 (pid_t) one_value_int);
				break;
			case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_virtual_process_id_tracker_handle_add_pid(
									 tracker_handle,
									 (pid_t) one_value_int) :
							 lttng_process_attr_virtual_process_id_tracker_handle_remove_pid(
									 tracker_handle,
									 (pid_t) one_value_int);
				break;
			case LTTNG_PROCESS_ATTR_USER_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_user_id_tracker_handle_add_uid(
									 tracker_handle,
									 (uid_t) one_value_int) :
							 lttng_process_attr_user_id_tracker_handle_remove_uid(
									 tracker_handle,
									 (uid_t) one_value_int);
				break;
			case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_virtual_user_id_tracker_handle_add_uid(
									 tracker_handle,
									 (uid_t) one_value_int) :
							 lttng_process_attr_virtual_user_id_tracker_handle_remove_uid(
									 tracker_handle,
									 (uid_t) one_value_int);
				break;
			case LTTNG_PROCESS_ATTR_GROUP_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_group_id_tracker_handle_add_gid(
									 tracker_handle,
									 (gid_t) one_value_int) :
							 lttng_process_attr_group_id_tracker_handle_remove_gid(
									 tracker_handle,
									 (gid_t) one_value_int);
				break;
			case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_virtual_group_id_tracker_handle_add_gid(
									 tracker_handle,
									 (gid_t) one_value_int) :
							 lttng_process_attr_virtual_group_id_tracker_handle_remove_gid(
									 tracker_handle,
									 (gid_t) one_value_int);
				break;
			default:
				abort();
			}

		} else {
			if (writer) {
				ret = mi_lttng_string_process_attribute_value(
						writer, process_attr,
						one_value_str, true);
				if (ret) {
					cmd_ret = CMD_FATAL;
					goto end;
				}
			}

			switch (process_attr) {
			case LTTNG_PROCESS_ATTR_USER_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_user_id_tracker_handle_add_user_name(
									 tracker_handle,
									 one_value_str) :
							 lttng_process_attr_user_id_tracker_handle_remove_user_name(
									 tracker_handle,
									 one_value_str);
				break;
			case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_virtual_user_id_tracker_handle_add_user_name(
									 tracker_handle,
									 one_value_str) :
							 lttng_process_attr_virtual_user_id_tracker_handle_remove_user_name(
									 tracker_handle,
									 one_value_str);
				break;
			case LTTNG_PROCESS_ATTR_GROUP_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_group_id_tracker_handle_add_group_name(
									 tracker_handle,
									 one_value_str) :
							 lttng_process_attr_group_id_tracker_handle_remove_group_name(
									 tracker_handle,
									 one_value_str);
				break;
			case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
				status = cmd_type == CMD_TRACK ?
							 lttng_process_attr_virtual_group_id_tracker_handle_add_group_name(
									 tracker_handle,
									 one_value_str) :
							 lttng_process_attr_virtual_group_id_tracker_handle_remove_group_name(
									 tracker_handle,
									 one_value_str);
				break;
			default:
				ERR("%s is not a valid %s value; expected an integer",
						one_value_str,
						lttng_process_attr_to_string(
								process_attr));
				cmd_ret = CMD_FATAL;
				goto end;
			}
		}

		ret = asprintf(&prettified_arg,
				is_numerical_argument ? "%s" : "`%s`",
				one_value_str);
		if (ret < 0) {
			PERROR("Failed to format argument `%s`", one_value_str);
			cmd_ret = CMD_FATAL;
			goto end;
		}

		switch (status) {
		case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK:
			if (cmd_type == CMD_TRACK) {
				MSG("Added %s to the %s tracker inclusion set",
						one_value_str,
						lttng_process_attr_to_string(
								process_attr));
			} else {
				MSG("Removed %s from the %s tracker inclusion set",
						one_value_str,
						lttng_process_attr_to_string(
								process_attr));
			}
			break;
		case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST:
			ERR("Session `%s` not found", session_name);
			break;
		case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_EXISTS:
			WARN("%s is already in the %s inclusion set",
					prettified_arg,
					lttng_process_attr_to_string(
							process_attr));
			break;
		case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_MISSING:
			WARN("%s is not in the %s the inclusion set",
					prettified_arg,
					lttng_process_attr_to_string(
							process_attr));
			break;
		case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_USER_NOT_FOUND:
			ERR("User %s was not found", prettified_arg);
			cmd_ret = CMD_ERROR;
			break;
		case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_GROUP_NOT_FOUND:
			ERR("Group %s was not found", prettified_arg);
			cmd_ret = CMD_ERROR;
			break;
		default:
			ERR("Unknown error encountered while %s %s %s %s tracker's inclusion set",
					cmd_type == CMD_TRACK ? "adding" :
								"removing",
					lttng_process_attr_to_string(
							process_attr),
					prettified_arg,
					cmd_type == CMD_TRACK ? "to" : "from");
			cmd_ret = CMD_FATAL;
			break;
		}
		free(prettified_arg);

		if (writer) {
			ret = mi_lttng_writer_write_element_bool(writer,
					mi_lttng_element_success,
					cmd_ret == CMD_SUCCESS);

			if (ret) {
				cmd_ret = CMD_FATAL;
			} else {
				ret = mi_lttng_writer_close_element(writer);
				cmd_ret = ret == 0 ? cmd_ret : CMD_FATAL;
			}
		}
	}
end:
	free(args);
	lttng_process_attr_tracker_handle_destroy(tracker_handle);
	return cmd_ret;
}

static enum cmd_error_code run_command(enum cmd_type cmd_type,
		const char *session_name,
		const struct process_attr_command_args *command_args,
		struct mi_writer *writer)
{
	const enum lttng_domain_type domain_type =
			opt_kernel ? LTTNG_DOMAIN_KERNEL : LTTNG_DOMAIN_UST;
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	unsigned int i;
	const unsigned int string_arg_count =
			lttng_dynamic_pointer_array_get_count(
					&command_args->string_args);
	enum lttng_process_attr process_attr = command_args->process_attr;

	if (opt_userspace) {
		/*
		 * Check that this process attribute can be tracked
		 * in the user space domain. Backward-compatibility
		 * changes are be applied to process_attr as needed.
		 */
		if (!ust_process_attr_supported(&process_attr)) {
			cmd_ret = CMD_ERROR;
			goto end;
		}
	}

	if (writer) {
		/* Open tracker and trackers elements */
		const int ret = mi_lttng_process_attribute_tracker_open(
				writer, process_attr);
		if (ret) {
			cmd_ret = CMD_FATAL;
			goto end;
		}
	}

	if (command_args->all) {
		cmd_ret = run_command_all(cmd_type, session_name, domain_type,
				process_attr, writer);
	} else {
		bool error_occurred = false;

		for (i = 0; i < string_arg_count; i++) {
			const char *arg = (const char *) lttng_dynamic_pointer_array_get_pointer(
					&command_args->string_args, i);

			cmd_ret = run_command_string(cmd_type, session_name,
					domain_type, process_attr, arg, writer);
			if (cmd_ret != CMD_SUCCESS) {
				error_occurred = true;
				if (cmd_ret == CMD_FATAL) {
					break;
				}
				goto end;
			}
		}
		if (error_occurred) {
			cmd_ret = CMD_ERROR;
		}
	}

	if (writer) {
		/* Close tracker and trackers elements */
		const int ret = mi_lttng_close_multi_element(
				writer, 2);
		if (ret) {
			cmd_ret = CMD_FATAL;
			goto end;
		}
	}
end:
	return cmd_ret;
}

/*
 * Add/remove tracker to/from session.
 */
static int cmd_track_untrack(enum cmd_type cmd_type,
		int argc,
		const char **argv,
		const char *help_msg __attribute__((unused)))
{
	int opt, ret = 0;
	bool sub_command_failed = false;
	bool opt_all = false;
	unsigned int selected_process_attr_tracker_count = 0;
	const unsigned int command_count =
			sizeof(process_attr_commands) /
			sizeof(struct process_attr_command_args);
	enum cmd_error_code command_ret = CMD_SUCCESS;
	static poptContext pc;
	char *session_name = NULL;
	const char *leftover = NULL;
	struct mi_writer *writer = NULL;
	size_t i;

	for (i = 0; i < command_count; i++) {
		process_attr_command_init(&process_attr_commands[i], (lttng_process_attr) i);
	}

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
		case OPT_VPID:
		case OPT_UID:
		case OPT_VUID:
		case OPT_GID:
		case OPT_VGID:
			/* See OPT_ enum declaration comment.  */
			opt--;
			selected_process_attr_tracker_count++;
			process_attr_commands[opt].requested = true;
			if (!opt_str_arg) {
				continue;
			}
			ret = lttng_dynamic_pointer_array_add_pointer(
					&process_attr_commands[opt].string_args,
					opt_str_arg);
			if (ret) {
				ERR("Allocation failed while parsing command arguments");
				command_ret = CMD_ERROR;
				goto end;
			}
			break;
		case OPT_ALL:
			opt_all = true;
			break;
		default:
			command_ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = print_missing_or_multiple_domains(
			opt_kernel + opt_userspace, false);
	if (ret) {
		command_ret = CMD_ERROR;
		goto end;
	}

	if (selected_process_attr_tracker_count == 0) {
		ERR("At least one process attribute must be specified");
		command_ret = CMD_ERROR;
		goto end;
	}
	if (opt_all) {
		/*
		 * Only one process attribute tracker was specified; find it
		 * and set it in 'all' mode.
		 */
		for (i = 0; i < command_count; i++) {
			if (!process_attr_commands[i].requested) {
				continue;
			}
			process_attr_commands[i].all = true;
			if (lttng_dynamic_pointer_array_get_count(
					    &process_attr_commands[i]
							     .string_args)) {
				ERR("The --all option cannot be used with a list of process attribute values");
				command_ret = CMD_ERROR;
				goto end;
			}
		}
	} else {
		for (i = 0; i < command_count; i++) {
			if (!process_attr_commands[i].requested) {
				continue;
			}
			if (lttng_dynamic_pointer_array_get_count(
				    &process_attr_commands[i]
				    .string_args) == 0) {
				ERR("No process attribute value specified for %s tracker",
						get_capitalized_process_attr_str(
								process_attr_commands[i]
										.process_attr));
				command_ret = CMD_ERROR;
				goto end;
			}
		}
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

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		command_ret = CMD_ERROR;
		goto end;
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

	/* Execute sub-commands. */
	for (i = 0; i < command_count; i++) {
		if (!process_attr_commands[i].requested) {
			continue;
		}
		command_ret = run_command(cmd_type, session_name,
				&process_attr_commands[i], writer);
		if (command_ret != CMD_SUCCESS) {
			sub_command_failed = true;
			if (command_ret == CMD_FATAL) {
				break;
			}
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
				mi_lttng_element_command_success,
				!sub_command_failed);
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

	for (i = 0; i < command_count; i++) {
		process_attr_command_fini(&process_attr_commands[i]);
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

	return cmd_track_untrack(CMD_TRACK, argc, argv, help_msg);
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

	return cmd_track_untrack(CMD_UNTRACK, argc, argv, help_msg);
}
