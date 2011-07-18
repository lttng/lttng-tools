/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTTNG_CMD_H
#define _LTTNG_CMD_H

#include <lttng/lttng.h>
#include "lttngerr.h"
#include "lttng-share.h"
#include "lttng-kernel.h"

enum cmd_error_code {
	CMD_SUCCESS,
	CMD_ERROR,
	CMD_UNDEFINED,
	CMD_NOT_IMPLEMENTED,
	CMD_FATAL,
};

struct cmd_struct {
	const char *name;
	int (*func)(int argc, const char **argv);
};

extern int cmd_list(int argc, const char **argv);
extern int cmd_create(int argc, const char **argv);
extern int cmd_destroy(int argc, const char **argv);
extern int cmd_start(int argc, const char **argv);
extern int cmd_stop(int argc, const char **argv);
extern int cmd_enable_events(int argc, const char **argv);
extern int cmd_disable_events(int argc, const char **argv);
extern int cmd_enable_channels(int argc, const char **argv);
extern int cmd_disable_channels(int argc, const char **argv);
extern int cmd_add_context(int argc, const char **argv);
extern int cmd_set_session(int argc, const char **argv);
extern int cmd_version(int argc, const char **argv);

#endif /* _LTTNG_CMD_H */
