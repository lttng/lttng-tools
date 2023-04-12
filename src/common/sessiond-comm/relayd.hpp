/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2012 Julien Desfossez <julien.desfossez@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _RELAYD_COMM
#define _RELAYD_COMM

#include <common/compiler.hpp>
#include <common/defaults.hpp>
#include <common/index/ctf-index.hpp>
#include <common/macros.hpp>
#include <common/optional.hpp>
#include <common/uuid.hpp>

#include <lttng/lttng.h>

#include <limits.h>
#include <stdint.h>

#define RELAYD_VERSION_COMM_MAJOR VERSION_MAJOR
#define RELAYD_VERSION_COMM_MINOR VERSION_MINOR

#define RELAYD_COMM_LTTNG_HOST_NAME_MAX_2_4 64
#define RELAYD_COMM_LTTNG_NAME_MAX_2_4	    255
#define RELAYD_COMM_LTTNG_PATH_MAX	    4096
#define RELAYD_COMM_DEFAULT_STREAM_NAME_LEN 264 /* 256 + 8 */

/*
 * lttng-relayd communication header.
 */
struct lttcomm_relayd_hdr {
	/* Circuit ID not used for now so always ignored */
	uint64_t circuit_id;
	uint64_t data_size; /* data size following this header */
	uint32_t cmd; /* enum lttcomm_relayd_command */
	uint32_t cmd_version; /* command version */
} LTTNG_PACKED;

/*
 * lttng-relayd data header.
 */
struct lttcomm_relayd_data_hdr {
	/* Circuit ID not used for now so always ignored */
	uint64_t circuit_id;
	uint64_t stream_id; /* Stream ID known by the relayd */
	uint64_t net_seq_num; /* Network sequence number, per stream. */
	uint32_t data_size; /* data size following this header */
	uint32_t padding_size; /* Size of 0 padding the data */
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
	char channel_name[RELAYD_COMM_DEFAULT_STREAM_NAME_LEN];
	char pathname[RELAYD_COMM_LTTNG_PATH_MAX];
} LTTNG_PACKED;

/*
 * Used to add a stream on the relay daemon.
 * Protocol version 2.2
 */
struct lttcomm_relayd_add_stream_2_2 {
	char channel_name[RELAYD_COMM_DEFAULT_STREAM_NAME_LEN];
	char pathname[RELAYD_COMM_LTTNG_PATH_MAX];
	uint64_t tracefile_size;
	uint64_t tracefile_count;
} LTTNG_PACKED;

struct lttcomm_relayd_add_stream_2_11 {
	uint32_t channel_name_len;
	uint32_t pathname_len;
	uint64_t tracefile_size;
	uint64_t tracefile_count;
	uint64_t trace_chunk_id;
	char names[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
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
	uint64_t last_net_seq_num; /* sequence number of last packet */
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
			return offsetof(struct lttcomm_relayd_index, stream_id) +
				member_sizeof(struct lttcomm_relayd_index, stream_id);
		case 1:
			return offsetof(struct lttcomm_relayd_index, packet_seq_num) +
				member_sizeof(struct lttcomm_relayd_index, packet_seq_num);
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
	char session_name[RELAYD_COMM_LTTNG_NAME_MAX_2_4];
	char hostname[RELAYD_COMM_LTTNG_HOST_NAME_MAX_2_4];
	uint32_t live_timer;
	uint32_t snapshot;
} LTTNG_PACKED;

struct lttcomm_relayd_create_session_2_11 {
	uint32_t session_name_len;
	uint32_t hostname_len;
	/* Optional, set to 0 to indicate it is not user-specified. */
	uint32_t base_path_len;
	uint32_t live_timer;
	uint8_t snapshot;
	uint8_t session_name_contains_creation_time;
	/* Sessiond instance UUID */
	uint8_t sessiond_uuid[LTTNG_UUID_LEN];
	/* Sessiond session id */
	uint64_t session_id;
	/* Session creation time, in seconds since UNIX Epoch. */
	uint64_t creation_time;
	LTTNG_OPTIONAL_COMM(uint64_t) LTTNG_PACKED current_chunk_id;
	/* Contains the session_name, hostname, base_path. */
	char names[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
} LTTNG_PACKED;

struct lttcomm_relayd_create_session_reply_2_11 {
	struct lttcomm_relayd_status_session generic;
	/* Includes the '\0' terminator. */
	uint32_t output_path_length;
	char output_path[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
} LTTNG_PACKED;

/*
 * Used to ask the relay to reset the metadata trace file (regeneration).
 * Send the new version of the metadata (starts at 0).
 */
struct lttcomm_relayd_reset_metadata {
	uint64_t stream_id;
	uint64_t version;
} LTTNG_PACKED;

struct lttcomm_relayd_stream_rotation_position {
	uint64_t stream_id;
	/*
	 * Sequence number of the first packet belonging to the new
	 * "destination" trace chunk to which the stream is rotating.
	 *
	 * Ignored for metadata streams.
	 */
	uint64_t rotate_at_seq_num;
} LTTNG_PACKED;

/*
 * For certain releases, the LTTNG_PACKED annotation was missing on the
 * `new_chunk_id` field which causes padding to be added between the
 * "optional" structure's `is_set` and `value` fields.
 *
 * Three alignment cases are handled:
 *   - `value` is aligned to the next byte boundary after `is_set`
 *     no padding is produced, see
 *     `struct lttcomm_relayd_rotate_streams_packed`,
 *   - `value` is aligned to the next 4-byte boundary after `is_set`
 *     (e.g. x86), 3 bytes of padding are produced, see
 *     `struct lttcomm_relayd_rotate_streams_3_bytes_padding`,
 *   - `value` is aligned to the next 8-byte boundary after `is_set`
 *     (e.g. x86-64), 7 bytes of padding are produced, see
 *     `struct lttcomm_relayd_rotate_streams_7_bytes_padding`.
 *
 * Note that since this structure's advertised size is used to determine
 * the size of the padding it includes, it can't be extended with new
 * optional fields. A new command would be needed.
 */
struct lttcomm_relayd_rotate_streams {
	uint32_t stream_count;
	/*
	 * Streams can be rotated outside of a chunk but not be parented to
	 * a new chunk.
	 *
	 * Improperly packed, but left as-is for backwards compatibility
	 * with unpatched relay daemons.
	 */
	LTTNG_OPTIONAL_COMM(uint64_t) new_chunk_id;
	/* `stream_count` positions follow. */
	struct lttcomm_relayd_stream_rotation_position rotation_positions[];
} LTTNG_PACKED;

struct lttcomm_relayd_rotate_streams_packed {
	uint32_t stream_count;
	LTTNG_OPTIONAL_COMM(uint64_t) LTTNG_PACKED new_chunk_id;
	struct lttcomm_relayd_stream_rotation_position rotation_positions[];
} LTTNG_PACKED;

struct lttcomm_relayd_rotate_streams_3_bytes_padding {
	uint32_t stream_count;
	struct {
		union {
			uint8_t is_set;
			uint32_t padding;
		};
		uint64_t value;
	} LTTNG_PACKED new_chunk_id;
	struct lttcomm_relayd_stream_rotation_position rotation_positions[];
} LTTNG_PACKED;

struct lttcomm_relayd_rotate_streams_7_bytes_padding {
	uint32_t stream_count;
	struct {
		union {
			uint8_t is_set;
			uint64_t padding;
		};
		uint64_t value;
	} LTTNG_PACKED new_chunk_id;
	struct lttcomm_relayd_stream_rotation_position rotation_positions[];
} LTTNG_PACKED;

struct lttcomm_relayd_create_trace_chunk {
	uint64_t chunk_id;
	/* Seconds since EPOCH. */
	uint64_t creation_timestamp;
	/* Includes trailing NULL. */
	uint32_t override_name_length;
	char override_name[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
} LTTNG_PACKED;

struct lttcomm_relayd_close_trace_chunk {
	uint64_t chunk_id;
	/* Seconds since EPOCH. */
	uint64_t close_timestamp;
	/* enum lttng_trace_chunk_command_type */
	LTTNG_OPTIONAL_COMM(uint32_t) LTTNG_PACKED close_command;
} LTTNG_PACKED;

struct lttcomm_relayd_close_trace_chunk_reply {
	struct lttcomm_relayd_generic_reply generic;
	/* Includes trailing NULL. */
	uint32_t path_length;
	char path[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
} LTTNG_PACKED;

struct lttcomm_relayd_trace_chunk_exists {
	uint64_t chunk_id;
} LTTNG_PACKED;

struct lttcomm_relayd_trace_chunk_exists_reply {
	struct lttcomm_relayd_generic_reply generic;
	uint8_t trace_chunk_exists;
} LTTNG_PACKED;

enum lttcomm_relayd_configuration_flag {
	/* The relay daemon (2.12) is configured to allow clear operations. */
	LTTCOMM_RELAYD_CONFIGURATION_FLAG_CLEAR_ALLOWED = (1 << 0),
};

struct lttcomm_relayd_get_configuration {
	uint64_t query_flags;
} LTTNG_PACKED;

/*
 * Used to return a relay daemon's configuration in reply to the
 * RELAYD_GET_CONFIGURATION command.
 */
struct lttcomm_relayd_get_configuration_reply {
	struct lttcomm_relayd_generic_reply generic;
	/* Set of lttcomm_relayd_configuration_flag. */
	uint64_t relayd_configuration_flags;
	/* Optional variable-length payload. */
	char payload[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
} LTTNG_PACKED;

#endif /* _RELAYD_COMM */
