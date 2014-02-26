/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _JUL_COMM
#define _JUL_COMM

#define _GNU_SOURCE
#include <stdint.h>

#include <lttng/lttng.h>

/*
 * Command value pass in the header.
 */
enum lttcomm_jul_command {
	JUL_CMD_LIST       = 1,
	JUL_CMD_ENABLE     = 2,
	JUL_CMD_DISABLE    = 3,
	JUL_CMD_REG_DONE   = 4,	/* End registration process. */
};

/*
 * Return code from the Java agent.
 */
enum lttcomm_jul_ret_code {
	JUL_RET_CODE_SUCCESS      = 1,
	JUL_RET_CODE_INVALID      = 2,
	JUL_RET_CODE_UNKNOWN_NAME = 3,
};

/*
 * JUL application communication header.
 */
struct lttcomm_jul_hdr {
	uint64_t data_size;		/* data size following this header */
	uint32_t cmd;			/* Enum of JUL command. */
	uint32_t cmd_version;	/* command version */
} LTTNG_PACKED;

/*
 * Enable event command payload.
 */
struct lttcomm_jul_enable {
	uint32_t loglevel;
	uint32_t loglevel_type;
	char name[LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

/*
 * Disable event command payload.
 */
struct lttcomm_jul_disable {
	char name[LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

/*
 * Generic reply coming from the Java Agent.
 */
struct lttcomm_jul_generic_reply {
	uint32_t ret_code;
} LTTNG_PACKED;

/*
 * List command reply header.
 */
struct lttcomm_jul_list_reply_hdr {
	uint32_t ret_code;
	uint32_t data_size;
} LTTNG_PACKED;

/*
 * List command reply payload coming from the Java Agent.
 */
struct lttcomm_jul_list_reply {
	uint32_t nb_event;
	/* List of event name each of them ending by a NULL byte. */
	char payload[];
} LTTNG_PACKED;

#endif	/* _JUL_COMM */
