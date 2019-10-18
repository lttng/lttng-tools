/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011-2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License only.
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

#ifndef _LTTNG_UST_CTL_H
#define _LTTNG_UST_CTL_H

#include <sys/types.h>

#include "lttng-ust-abi.h"

#ifndef LTTNG_UST_UUID_LEN
#define LTTNG_UST_UUID_LEN	16
#endif

/* Default unix socket path */
#define LTTNG_UST_SOCK_FILENAME					\
	"lttng-ust-sock-"					\
	__ust_stringify(LTTNG_UST_ABI_MAJOR_VERSION)

/*
 * Shared memory files path are automatically related to shm root, e.g.
 * /dev/shm under linux.
 */
#define LTTNG_UST_WAIT_FILENAME					\
	"lttng-ust-wait-"					\
	__ust_stringify(LTTNG_UST_ABI_MAJOR_VERSION)

struct lttng_ust_shm_handle;
struct lttng_ust_lib_ring_buffer;

struct ustctl_consumer_channel_attr {
	enum lttng_ust_chan_type type;
	uint64_t subbuf_size;			/* bytes, power of 2 */
	uint64_t num_subbuf;			/* power of 2 */
	int overwrite;				/* 1: overwrite, 0: discard */
	unsigned int switch_timer_interval;	/* usec */
	unsigned int read_timer_interval;	/* usec */
	enum lttng_ust_output output;		/* splice, mmap */
	uint32_t chan_id;           /* channel ID */
	unsigned char uuid[LTTNG_UST_UUID_LEN]; /* Trace session unique ID */
	int64_t blocking_timeout;			/* Retry timeout (usec) */
} LTTNG_PACKED;

/*
 * API used by sessiond.
 */

struct lttng_ust_context_attr {
	enum lttng_ust_context_type ctx;
	union {
		struct lttng_ust_perf_counter_ctx perf_counter;
		struct {
		        char *provider_name;
			char *ctx_name;
		} app_ctx;
	} u;
};

/*
 * Error values: all the following functions return:
 * >= 0: Success (LTTNG_UST_OK)
 * < 0: error code.
 */
int ustctl_register_done(int sock);
int ustctl_create_session(int sock);
int ustctl_create_event(int sock, struct lttng_ust_event *ev,
		struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data **event_data);
int ustctl_add_context(int sock, struct lttng_ust_context_attr *ctx,
		struct lttng_ust_object_data *obj_data,
		struct lttng_ust_object_data **context_data);
int ustctl_set_filter(int sock, struct lttng_ust_filter_bytecode *bytecode,
		struct lttng_ust_object_data *obj_data);

int ustctl_enable(int sock, struct lttng_ust_object_data *object);
int ustctl_disable(int sock, struct lttng_ust_object_data *object);
int ustctl_start_session(int sock, int handle);
int ustctl_stop_session(int sock, int handle);

/*
 * ustctl_tracepoint_list returns a tracepoint list handle, or negative
 * error value.
 */
int ustctl_tracepoint_list(int sock);

/*
 * ustctl_tracepoint_list_get is used to iterate on the tp list
 * handle. End is iteration is reached when -LTTNG_UST_ERR_NOENT is
 * returned.
 */
int ustctl_tracepoint_list_get(int sock, int tp_list_handle,
		struct lttng_ust_tracepoint_iter *iter);

/*
 * ustctl_tracepoint_field_list returns a tracepoint field list handle,
 * or negative error value.
 */
int ustctl_tracepoint_field_list(int sock);

/*
 * ustctl_tracepoint_field_list_get is used to iterate on the tp field
 * list handle. End is iteration is reached when -LTTNG_UST_ERR_NOENT is
 * returned.
 */
int ustctl_tracepoint_field_list_get(int sock, int tp_field_list_handle,
		struct lttng_ust_field_iter *iter);

int ustctl_tracer_version(int sock, struct lttng_ust_tracer_version *v);
int ustctl_wait_quiescent(int sock);

int ustctl_sock_flush_buffer(int sock, struct lttng_ust_object_data *object);

/* Release object created by members of this API. */
int ustctl_release_object(int sock, struct lttng_ust_object_data *data);
/* Release handle returned by create session. */
int ustctl_release_handle(int sock, int handle);

int ustctl_recv_channel_from_consumer(int sock,
		struct lttng_ust_object_data **channel_data);
int ustctl_recv_stream_from_consumer(int sock,
		struct lttng_ust_object_data **stream_data);
int ustctl_send_channel_to_ust(int sock, int session_handle,
		struct lttng_ust_object_data *channel_data);
int ustctl_send_stream_to_ust(int sock,
		struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data *stream_data);

/*
 * ustctl_duplicate_ust_object_data allocated a new object in "dest" if
 * it succeeds (returns 0). It must be released using
 * ustctl_release_object() and then freed with free().
 */
int ustctl_duplicate_ust_object_data(struct lttng_ust_object_data **dest,
		struct lttng_ust_object_data *src);

/*
 * API used by consumer.
 */

struct ustctl_consumer_channel;
struct ustctl_consumer_stream;
struct ustctl_consumer_channel_attr;

struct ustctl_consumer_channel *
	ustctl_create_channel(struct ustctl_consumer_channel_attr *attr);
/*
 * Each stream created needs to be destroyed before calling
 * ustctl_destroy_channel().
 */
void ustctl_destroy_channel(struct ustctl_consumer_channel *chan);

int ustctl_send_channel_to_sessiond(int sock,
		struct ustctl_consumer_channel *channel);
int ustctl_channel_close_wait_fd(struct ustctl_consumer_channel *consumer_chan);
int ustctl_channel_close_wakeup_fd(struct ustctl_consumer_channel *consumer_chan);
int ustctl_channel_get_wait_fd(struct ustctl_consumer_channel *consumer_chan);
int ustctl_channel_get_wakeup_fd(struct ustctl_consumer_channel *consumer_chan);

int ustctl_write_metadata_to_channel(
		struct ustctl_consumer_channel *channel,
		const char *metadata_str,	/* NOT null-terminated */
		size_t len);			/* metadata length */

/*
 * Send a NULL stream to finish iteration over all streams of a given
 * channel.
 */
int ustctl_send_stream_to_sessiond(int sock,
		struct ustctl_consumer_stream *stream);
int ustctl_stream_close_wait_fd(struct ustctl_consumer_stream *stream);
int ustctl_stream_close_wakeup_fd(struct ustctl_consumer_stream *stream);
int ustctl_stream_get_wait_fd(struct ustctl_consumer_stream *stream);
int ustctl_stream_get_wakeup_fd(struct ustctl_consumer_stream *stream);

/* Create/destroy stream buffers for read */
struct ustctl_consumer_stream *
	ustctl_create_stream(struct ustctl_consumer_channel *channel,
			int cpu);
void ustctl_destroy_stream(struct ustctl_consumer_stream *stream);

/* For mmap mode, readable without "get" operation */
int ustctl_get_mmap_len(struct ustctl_consumer_stream *stream,
		unsigned long *len);
int ustctl_get_max_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len);

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */
void *ustctl_get_mmap_base(struct ustctl_consumer_stream *stream);
int ustctl_get_mmap_read_offset(struct ustctl_consumer_stream *stream,
		unsigned long *off);
int ustctl_get_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len);
int ustctl_get_padded_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len);
int ustctl_get_next_subbuf(struct ustctl_consumer_stream *stream);
int ustctl_put_next_subbuf(struct ustctl_consumer_stream *stream);

/* snapshot */

int ustctl_snapshot(struct ustctl_consumer_stream *stream);
int ustctl_snapshot_sample_positions(struct ustctl_consumer_stream *stream);
int ustctl_snapshot_get_consumed(struct ustctl_consumer_stream *stream,
		unsigned long *pos);
int ustctl_snapshot_get_produced(struct ustctl_consumer_stream *stream,
		unsigned long *pos);
int ustctl_get_subbuf(struct ustctl_consumer_stream *stream,
		unsigned long *pos);
int ustctl_put_subbuf(struct ustctl_consumer_stream *stream);

void ustctl_flush_buffer(struct ustctl_consumer_stream *stream,
		int producer_active);

/* event registry management */

enum ustctl_socket_type {
	USTCTL_SOCKET_CMD = 0,
	USTCTL_SOCKET_NOTIFY = 1,
};

enum ustctl_notify_cmd {
	USTCTL_NOTIFY_CMD_EVENT = 0,
	USTCTL_NOTIFY_CMD_CHANNEL = 1,
	USTCTL_NOTIFY_CMD_ENUM = 2,
};

enum ustctl_channel_header {
	USTCTL_CHANNEL_HEADER_UNKNOWN = 0,
	USTCTL_CHANNEL_HEADER_COMPACT = 1,
	USTCTL_CHANNEL_HEADER_LARGE = 2,
};

/* event type structures */

enum ustctl_abstract_types {
	ustctl_atype_integer,
	ustctl_atype_enum,
	ustctl_atype_array,
	ustctl_atype_sequence,
	ustctl_atype_string,
	ustctl_atype_float,
	NR_USTCTL_ABSTRACT_TYPES,
};

enum ustctl_string_encodings {
	ustctl_encode_none = 0,
	ustctl_encode_UTF8 = 1,
	ustctl_encode_ASCII = 2,
	NR_USTCTL_STRING_ENCODINGS,
};

#define USTCTL_UST_INTEGER_TYPE_PADDING	24
struct ustctl_integer_type {
	uint32_t size;		/* in bits */
	uint32_t signedness;
	uint32_t reverse_byte_order;
	uint32_t base;		/* 2, 8, 10, 16, for pretty print */
	int32_t encoding;
	uint16_t alignment;	/* in bits */
	char padding[USTCTL_UST_INTEGER_TYPE_PADDING];
} LTTNG_PACKED;

#define USTCTL_UST_FLOAT_TYPE_PADDING	24
struct ustctl_float_type {
	uint32_t exp_dig;		/* exponent digits, in bits */
	uint32_t mant_dig;		/* mantissa digits, in bits */
	uint32_t reverse_byte_order;
	uint16_t alignment;	/* in bits */
	char padding[USTCTL_UST_FLOAT_TYPE_PADDING];
} LTTNG_PACKED;

#define USTCTL_UST_ENUM_VALUE_PADDING	15
struct ustctl_enum_value {
	uint64_t value;
	uint8_t signedness;
	char padding[USTCTL_UST_ENUM_VALUE_PADDING];
} LTTNG_PACKED;

enum ustctl_ust_enum_entry_options {
	USTCTL_UST_ENUM_ENTRY_OPTION_IS_AUTO = 1U << 0,
};

#define USTCTL_UST_ENUM_ENTRY_PADDING	32
struct ustctl_enum_entry {
	struct ustctl_enum_value start, end; /* start and end are inclusive */
	char string[LTTNG_UST_SYM_NAME_LEN];
	union {
		struct {
			uint32_t options;
		} LTTNG_PACKED extra;
		char padding[USTCTL_UST_ENUM_ENTRY_PADDING];
	} u;
} LTTNG_PACKED;

#define USTCTL_UST_BASIC_TYPE_PADDING	296
union _ustctl_basic_type {
	struct ustctl_integer_type integer;
	struct {
		int32_t encoding;
	} string;
	struct ustctl_float_type _float;
	struct {
		char name[LTTNG_UST_SYM_NAME_LEN];
	} enumeration;
	char padding[USTCTL_UST_BASIC_TYPE_PADDING];
} LTTNG_PACKED;

struct ustctl_basic_type {
	enum ustctl_abstract_types atype;
	union {
		union _ustctl_basic_type basic;
	} u;
} LTTNG_PACKED;

#define USTCTL_UST_TYPE_PADDING	128
struct ustctl_type {
	enum ustctl_abstract_types atype;
	union {
		union _ustctl_basic_type basic;
		struct {
			struct ustctl_basic_type elem_type;
			uint32_t length;		/* num. elems. */
		} array;
		struct {
			struct ustctl_basic_type length_type;
			struct ustctl_basic_type elem_type;
		} sequence;
		char padding[USTCTL_UST_TYPE_PADDING];
	} u;
} LTTNG_PACKED;

#define USTCTL_UST_FIELD_PADDING	28
struct ustctl_field {
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct ustctl_type type;
	char padding[USTCTL_UST_FIELD_PADDING];
} LTTNG_PACKED;

/*
 * Returns 0 on success, negative error value on error.
 * If an error other than -LTTNG_UST_ERR_UNSUP_MAJOR is returned,
 * the output fields are not populated.
 */
int ustctl_recv_reg_msg(int sock,
	enum ustctl_socket_type *type,
	uint32_t *major,
	uint32_t *minor,
	uint32_t *pid,
	uint32_t *ppid,
	uint32_t *uid,
	uint32_t *gid,
	uint32_t *bits_per_long,
	uint32_t *uint8_t_alignment,
	uint32_t *uint16_t_alignment,
	uint32_t *uint32_t_alignment,
	uint32_t *uint64_t_alignment,
	uint32_t *long_alignment,
	int *byte_order,
	char *name);	/* size LTTNG_UST_ABI_PROCNAME_LEN */

/*
 * Returns 0 on success, negative UST or system error value on error.
 * Receive the notification command. The "notify_cmd" can then be used
 * by the caller to find out which ustctl_recv_* function should be
 * called to receive the notification, and which ustctl_reply_* is
 * appropriate.
 */
int ustctl_recv_notify(int sock, enum ustctl_notify_cmd *notify_cmd);

/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int ustctl_recv_register_event(int sock,
	int *session_objd,		/* session descriptor (output) */
	int *channel_objd,		/* channel descriptor (output) */
	char *event_name,		/*
					 * event name (output,
					 * size LTTNG_UST_SYM_NAME_LEN)
					 */
	int *loglevel_value,
	char **signature,		/*
					 * event signature
					 * (output, dynamically
					 * allocated, must be free(3)'d
					 * by the caller if function
					 * returns success.)
					 */
	size_t *nr_fields,
	struct ustctl_field **fields,
	char **model_emf_uri);

/*
 * Returns 0 on success, negative error value on error.
 */
int ustctl_reply_register_event(int sock,
	uint32_t id,			/* event id (input) */
	int ret_code);			/* return code. 0 ok, negative error */

/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int ustctl_recv_register_enum(int sock,
	int *session_objd,
	char *enum_name,
	struct ustctl_enum_entry **entries,
	unsigned int *nr_entries);

/*
 * Returns 0 on success, negative error value on error.
 */
int ustctl_reply_register_enum(int sock,
	int64_t id,			/* enum id (input) */
	int ret_code);

/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int ustctl_recv_register_channel(int sock,
	int *session_objd,		/* session descriptor (output) */
	int *channel_objd,		/* channel descriptor (output) */
	size_t *nr_fields,		/* context fields */
	struct ustctl_field **fields);

/*
 * Returns 0 on success, negative error value on error.
 */
int ustctl_reply_register_channel(int sock,
	uint32_t chan_id,
	enum ustctl_channel_header header_type,
	int ret_code);			/* return code. 0 ok, negative error */

#endif /* _LTTNG_UST_CTL_H */
