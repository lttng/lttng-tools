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

#include <limits.h>
#include <stdint.h>

#include <lttng/lttng.h>
#include <common/defaults.h>
#include <common/index/ctf-index.h>

#define RELAYD_VERSION_COMM_MAJOR             VERSION_MAJOR
#define RELAYD_VERSION_COMM_MINOR             VERSION_MINOR

/*
 * lttng-relayd communication header.
 */
struct lttcomm_relayd_hdr {
	/* Circuit ID not used for now so always ignored */
	uint64_t circuit_id;
	uint64_t data_size;		/* data size following this header */
	uint32_t cmd;			/* enum lttcomm_relayd_command */
	uint32_t cmd_version;	/* command version */
} LTTNG_PACKED;

/*
 * lttng-relayd data header.
 */
struct lttcomm_relayd_data_hdr {
	/* Circuit ID not used for now so always ignored */
	uint64_t circuit_id;
	uint64_t stream_id;     /* Stream ID known by the relayd */
	uint64_t net_seq_num;   /* Network sequence number, per stream. */
	uint32_t data_size;     /* data size following this header */
	uint32_t padding_size;  /* Size of 0 padding the data */
} LTTNG_PACKED;

/*
 * Reply from a create session command.
 */
struct lttcomm_relayd_status_session {
	uint64_t session_id;
	uint32_t ret_code;
} LTTNG_PACKED;

/*
 * Used to add a stream on the relay daemon.
 */
struct lttcomm_relayd_add_stream {
	char channel_name[DEFAULT_STREAM_NAME_LEN];
	char pathname[LTTNG_PATH_MAX];
} LTTNG_PACKED;

/*
 * Used to add a stream on the relay daemon.
 * Protocol version 2.2
 */
struct lttcomm_relayd_add_stream_2_2 {
	char channel_name[DEFAULT_STREAM_NAME_LEN];
	char pathname[LTTNG_PATH_MAX];
	uint64_t tracefile_size;
	uint64_t tracefile_count;
} LTTNG_PACKED;

/*
 * Answer from an add stream command.
 */
struct lttcomm_relayd_status_stream {
	uint64_t handle;
	uint32_t ret_code;
} LTTNG_PACKED;

/*
 * Used to return command code for command not needing special data.
 */
struct lttcomm_relayd_generic_reply {
	uint32_t ret_code;
} LTTNG_PACKED;

/*
 * Version command.
 */
struct lttcomm_relayd_version {
	uint32_t major;
	uint32_t minor;
} LTTNG_PACKED;

/*
 * Metadata payload used when metadata command is sent.
 */
struct lttcomm_relayd_metadata_payload {
	uint64_t stream_id;
	uint32_t padding_size;
	char payload[];
} LTTNG_PACKED;

/*
 * Used to indicate that a specific stream id can now be closed.
 */
struct lttcomm_relayd_close_stream {
	uint64_t stream_id;
	uint64_t last_net_seq_num;	/* sequence number of last packet */
} LTTNG_PACKED;

/*
 * Used to test if for a given stream id the data is pending on the relayd side
 * for reading.
 */
struct lttcomm_relayd_data_pending {
	uint64_t stream_id;
	uint64_t last_net_seq_num; /* Sequence number of the last packet */
} LTTNG_PACKED;

struct lttcomm_relayd_begin_data_pending {
	uint64_t session_id;
} LTTNG_PACKED;

struct lttcomm_relayd_end_data_pending {
	uint64_t session_id;
} LTTNG_PACKED;

struct lttcomm_relayd_quiescent_control {
	uint64_t stream_id;
} LTTNG_PACKED;

/*
 * Index data.
 */
struct lttcomm_relayd_index {
	uint64_t relay_stream_id;
	uint64_t net_seq_num;
	uint64_t packet_size;
	uint64_t content_size;
	uint64_t timestamp_begin;
	uint64_t timestamp_end;
	uint64_t events_discarded;
	uint64_t stream_id;
	/* 2.8+ */
	uint64_t stream_instance_id;
	uint64_t packet_seq_num;
} LTTNG_PACKED;

static inline size_t lttcomm_relayd_index_len(uint32_t major, uint32_t minor)
{
	if (major == 1) {
		switch (minor) {
		case 0:
			return offsetof(struct lttcomm_relayd_index, stream_id)
				+ member_sizeof(struct lttcomm_relayd_index,
						stream_id);
		case 1:
			return offsetof(struct lttcomm_relayd_index, packet_seq_num)
				+ member_sizeof(struct lttcomm_relayd_index,
						packet_seq_num);
		default:
			abort();
		}
	}
	abort();
}

/*
 * Create session in 2.4 adds additionnal parameters for live reading.
 */
struct lttcomm_relayd_create_session_2_4 {
	char session_name[LTTNG_NAME_MAX];
	char hostname[LTTNG_HOST_NAME_MAX];
	uint32_t live_timer;
	uint32_t snapshot;
} LTTNG_PACKED;

/*
 * Used to ask the relay to reset the metadata trace file (regeneration).
 * Send the new version of the metadata (starts at 0).
 */
struct lttcomm_relayd_reset_metadata {
	uint64_t stream_id;
	uint64_t version;
} LTTNG_PACKED;

#endif	/* _RELAYD_COMM */
