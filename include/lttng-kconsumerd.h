/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only verion 2
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

#ifndef _LTTNG_KCONSUMERD_H
#define _LTTNG_KCONSUMERD_H

#include <lttng-sessiond-comm.h>
#include "lttng-share.h"

/* Kernel consumer path */
#define KCONSUMERD_PATH					LTTNG_RUNDIR "/kconsumerd"
#define KCONSUMERD_CMD_SOCK_PATH			KCONSUMERD_PATH "/command"
#define KCONSUMERD_ERR_SOCK_PATH			KCONSUMERD_PATH "/error"

/* Commands for kconsumerd */
enum kconsumerd_command {
	ADD_STREAM,
	UPDATE_STREAM, /* pause, delete, active depending on fd state */
	STOP, /* inform the kconsumerd to quit when all fd has hang up */
};

/* State of each fd in consumerd */
enum kconsumerd_fd_state {
	ACTIVE_FD,
	PAUSE_FD,
	DELETE_FD,
};

#endif /* _LTTNG_KCONSUMERD_H */
