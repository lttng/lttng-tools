/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *                      Julien Desfossez <julien.desfossez@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _RELAYD_COMM
#define _RELAYD_COMM

#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>

#include <lttng/lttng.h>

/*
 * lttng-relayd communication header.
 */
struct lttcomm_relayd_hdr {
	/* Circuit ID not used for now so always ignored */
	uint64_t circuit_id;
	uint64_t data_size;		/* data size following this header */
	uint32_t cmd;			/* enum lttcomm_sessiond_command */
	uint32_t cmd_version;	/* command version */
} __attribute__ ((__packed__));

/*
 * lttng-relayd data header.
 */
struct lttcomm_relayd_data_hdr {
	/* Circuit ID not used for now so always ignored */
	uint64_t circuit_id;
	uint64_t stream_id;     /* Stream ID known by the relayd */
	uint64_t net_seq_num;   /* Network seq. number for UDP. */
	uint32_t data_size;     /* data size following this header */
} __attribute__ ((__packed__));

#if 0
/*
 * Used to create a session between the relay and the sessiond.
 */
struct lttcomm_relayd_create_session {
	char hostname[LTTNG_MAX_DNNAME];
	char session_name[NAME_MAX];
};
#endif

/*
 * Used to add a stream on the relay daemon.
 */
struct lttcomm_relayd_add_stream {
	char channel_name[LTTNG_SYMBOL_NAME_LEN];
	char pathname[PATH_MAX];
} __attribute__ ((__packed__));

/*
 * Answer from an add stream command.
 */
struct lttcomm_relayd_status_stream {
	uint64_t handle;
	uint32_t ret_code;
} __attribute__ ((__packed__));

/*
 * Used to return command code for command not needing special data.
 */
struct lttcomm_relayd_generic_reply {
	uint32_t ret_code;
} __attribute__ ((__packed__));

/*
 * Used to update synchronization information.
 */
struct lttcomm_relayd_update_sync_info {
	/* TODO: fill the structure */
} __attribute__ ((__packed__));

/*
 * Version command.
 */
struct lttcomm_relayd_version {
	uint32_t major;
	uint32_t minor;
} __attribute__ ((__packed__));

/*
 * Metadata payload used when metadata command is sent.
 */
struct lttcomm_relayd_metadata_payload {
	uint64_t stream_id;
	char payload[];
} __attribute__ ((__packed__));

#endif	/* _RELAYD_COMM */
