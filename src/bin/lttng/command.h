/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_CMD_H
#define _LTTNG_CMD_H

#include <lttng/lttng.h>
#include <common/common.h>
#include <common/defaults.h>

#include "conf.h"
#include "utils.h"

#define DECL_COMMAND(_name) \
	extern int cmd_##_name(int, const char **)

#ifdef LTTNG_EMBED_HELP
# define HELP_MSG_NAME		help_msg
# define SHOW_HELP_ERROR_LINE	ERR("Cannot show --help for `lttng-%s`", argv[0]);
#else
# define HELP_MSG_NAME		NULL
# define SHOW_HELP_ERROR_LINE	;
#endif

#define SHOW_HELP() 							\
	do {								\
		ret = show_cmd_help(argv[0], HELP_MSG_NAME);		\
									\
		if (ret) {						\
			SHOW_HELP_ERROR_LINE 				\
			ret = CMD_ERROR;				\
		}							\
	} while (0)

enum cmd_error_code {
	CMD_SUCCESS = 0,
	CMD_ERROR,
	CMD_UNDEFINED,
	CMD_FATAL,
	CMD_WARNING,
	CMD_UNSUPPORTED,
};

struct cmd_struct {
	const char *name;
	int (*func)(int argc, const char **argv);
};

DECL_COMMAND(list);
DECL_COMMAND(status);
DECL_COMMAND(create);
DECL_COMMAND(destroy);
DECL_COMMAND(start);
DECL_COMMAND(stop);
DECL_COMMAND(enable_events);
DECL_COMMAND(disable_events);
DECL_COMMAND(enable_channels);
DECL_COMMAND(disable_channels);
DECL_COMMAND(add_context);
DECL_COMMAND(set_session);
DECL_COMMAND(version);
DECL_COMMAND(view);
DECL_COMMAND(enable_consumer);
DECL_COMMAND(disable_consumer);
DECL_COMMAND(snapshot);
DECL_COMMAND(save);
DECL_COMMAND(load);
DECL_COMMAND(track);
DECL_COMMAND(untrack);
DECL_COMMAND(metadata);
DECL_COMMAND(regenerate);
DECL_COMMAND(rotate);
DECL_COMMAND(enable_rotation);
DECL_COMMAND(disable_rotation);
DECL_COMMAND(clear);
DECL_COMMAND(add_trigger);
DECL_COMMAND(list_triggers);
DECL_COMMAND(remove_trigger);

extern int cmd_help(int argc, const char **argv,
		const struct cmd_struct commands[]);

#endif /* _LTTNG_CMD_H */
