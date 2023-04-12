/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_CTL_INTERNAL_H
#define LTTNG_UST_CTL_INTERNAL_H

#include "lttng-ust-abi.hpp"

#include <limits.h>
#include <sys/types.h>

#ifndef LTTNG_UST_UUID_LEN
#define LTTNG_UST_UUID_LEN 16
#endif

/* Default unix socket path */
#define LTTNG_UST_SOCK_FILENAME \
	"lttng-ust-sock-" __ust_stringify(LTTNG_UST_ABI_MAJOR_VERSION_OLDEST_COMPATIBLE)

/*
 * Shared memory files path are automatically related to shm root, e.g.
 * /dev/shm under linux.
 */
#define LTTNG_UST_WAIT_FILENAME \
	"lttng-ust-wait-" __ust_stringify(LTTNG_UST_ABI_MAJOR_VERSION_OLDEST_COMPATIBLE)

struct lttng_ust_shm_handle;
struct lttng_ust_lib_ring_buffer;

struct lttng_ust_ctl_consumer_channel_attr {
	enum lttng_ust_abi_chan_type type;
	uint64_t subbuf_size; /* bytes */
	uint64_t num_subbuf; /* power of 2 */
	int overwrite; /* 1: overwrite, 0: discard */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval; /* usec */
	enum lttng_ust_abi_output output; /* splice, mmap */
	uint32_t chan_id; /* channel ID */
	unsigned char uuid[LTTNG_UST_UUID_LEN]; /* Trace session unique ID */
	int64_t blocking_timeout; /* Blocking timeout (usec) */
} LTTNG_PACKED;

/*
 * API used by sessiond.
 */

struct lttng_ust_context_attr {
	enum lttng_ust_abi_context_type ctx;
	union {
		struct lttng_ust_abi_perf_counter_ctx perf_counter;
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
int lttng_ust_ctl_register_done(int sock);
int lttng_ust_ctl_create_session(int sock);
int lttng_ust_ctl_create_event(int sock,
			       struct lttng_ust_abi_event *ev,
			       struct lttng_ust_abi_object_data *channel_data,
			       struct lttng_ust_abi_object_data **event_data);
int lttng_ust_ctl_add_context(int sock,
			      struct lttng_ust_context_attr *ctx,
			      struct lttng_ust_abi_object_data *obj_data,
			      struct lttng_ust_abi_object_data **context_data);
int lttng_ust_ctl_set_filter(int sock,
			     struct lttng_ust_abi_filter_bytecode *bytecode,
			     struct lttng_ust_abi_object_data *obj_data);
int lttng_ust_ctl_set_capture(int sock,
			      struct lttng_ust_abi_capture_bytecode *bytecode,
			      struct lttng_ust_abi_object_data *obj_data);
int lttng_ust_ctl_set_exclusion(int sock,
				struct lttng_ust_abi_event_exclusion *exclusion,
				struct lttng_ust_abi_object_data *obj_data);

int lttng_ust_ctl_enable(int sock, struct lttng_ust_abi_object_data *object);
int lttng_ust_ctl_disable(int sock, struct lttng_ust_abi_object_data *object);
int lttng_ust_ctl_start_session(int sock, int handle);
int lttng_ust_ctl_stop_session(int sock, int handle);

/*
 * lttng_ust_ctl_create_event notifier_group creates a event notifier group. It
 * establishes the connection with the application by providing a file
 * descriptor of the pipe to be used by the application when a event notifier
 * of that group is fired. It returns a handle to be used when creating event
 * notifier in that group.
 */
int lttng_ust_ctl_create_event_notifier_group(
	int sock, int pipe_fd, struct lttng_ust_abi_object_data **event_notifier_group);

/*
 * lttng_ust_ctl_create_event notifier creates a event notifier in a event notifier
 * group giving a event notifier description and a event notifier group handle.
 * It returns a event notifier handle to be used when enabling the event
 * notifier, attaching filter, attaching exclusion, and disabling the event
 * notifier.
 */
int lttng_ust_ctl_create_event_notifier(int sock,
					struct lttng_ust_abi_event_notifier *event_notifier,
					struct lttng_ust_abi_object_data *event_notifier_group,
					struct lttng_ust_abi_object_data **event_notifier_data);

/*
 * lttng_ust_ctl_tracepoint_list returns a tracepoint list handle, or negative
 * error value.
 */
int lttng_ust_ctl_tracepoint_list(int sock);

/*
 * lttng_ust_ctl_tracepoint_list_get is used to iterate on the tp list
 * handle. End is iteration is reached when -LTTNG_UST_ERR_NOENT is
 * returned.
 */
int lttng_ust_ctl_tracepoint_list_get(int sock,
				      int tp_list_handle,
				      struct lttng_ust_abi_tracepoint_iter *iter);

/*
 * lttng_ust_ctl_tracepoint_field_list returns a tracepoint field list handle,
 * or negative error value.
 */
int lttng_ust_ctl_tracepoint_field_list(int sock);

/*
 * lttng_ust_ctl_tracepoint_field_list_get is used to iterate on the tp field
 * list handle. End is iteration is reached when -LTTNG_UST_ERR_NOENT is
 * returned.
 */
int lttng_ust_ctl_tracepoint_field_list_get(int sock,
					    int tp_field_list_handle,
					    struct lttng_ust_abi_field_iter *iter);

int lttng_ust_ctl_tracer_version(int sock, struct lttng_ust_abi_tracer_version *v);
int lttng_ust_ctl_wait_quiescent(int sock);

int lttng_ust_ctl_sock_flush_buffer(int sock, struct lttng_ust_abi_object_data *object);

int lttng_ust_ctl_calibrate(int sock, struct lttng_ust_abi_calibrate *calibrate);

/* Release object created by members of this API. */
int lttng_ust_ctl_release_object(int sock, struct lttng_ust_abi_object_data *data);
/* Release handle returned by create session. */
int lttng_ust_ctl_release_handle(int sock, int handle);

int lttng_ust_ctl_recv_channel_from_consumer(int sock,
					     struct lttng_ust_abi_object_data **channel_data);
int lttng_ust_ctl_recv_stream_from_consumer(int sock,
					    struct lttng_ust_abi_object_data **stream_data);
int lttng_ust_ctl_send_channel_to_ust(int sock,
				      int session_handle,
				      struct lttng_ust_abi_object_data *channel_data);
int lttng_ust_ctl_send_stream_to_ust(int sock,
				     struct lttng_ust_abi_object_data *channel_data,
				     struct lttng_ust_abi_object_data *stream_data);

/*
 * lttng_ust_ctl_duplicate_ust_object_data allocated a new object in "dest" if
 * it succeeds (returns 0). It must be released using
 * lttng_ust_ctl_release_object() and then freed with free().
 */
int lttng_ust_ctl_duplicate_ust_object_data(struct lttng_ust_abi_object_data **dest,
					    struct lttng_ust_abi_object_data *src);

/*
 * API used by consumer.
 */

struct lttng_ust_ctl_consumer_channel;
struct lttng_ust_ctl_consumer_stream;
struct lttng_ust_ctl_consumer_channel_attr;

int lttng_ust_ctl_get_nr_stream_per_channel(void);

struct lttng_ust_ctl_consumer_channel *lttng_ust_ctl_create_channel(
	struct lttng_ust_ctl_consumer_channel_attr *attr, const int *stream_fds, int nr_stream_fds);
/*
 * Each stream created needs to be destroyed before calling
 * lttng_ust_ctl_destroy_channel().
 */
void lttng_ust_ctl_destroy_channel(struct lttng_ust_ctl_consumer_channel *chan);

int lttng_ust_ctl_send_channel_to_sessiond(int sock,
					   struct lttng_ust_ctl_consumer_channel *channel);
int lttng_ust_ctl_channel_close_wait_fd(struct lttng_ust_ctl_consumer_channel *consumer_chan);
int lttng_ust_ctl_channel_close_wakeup_fd(struct lttng_ust_ctl_consumer_channel *consumer_chan);
int lttng_ust_ctl_channel_get_wait_fd(struct lttng_ust_ctl_consumer_channel *consumer_chan);
int lttng_ust_ctl_channel_get_wakeup_fd(struct lttng_ust_ctl_consumer_channel *consumer_chan);

int lttng_ust_ctl_write_metadata_to_channel(struct lttng_ust_ctl_consumer_channel *channel,
					    const char *metadata_str, /* NOT null-terminated */
					    size_t len); /* metadata length */
ssize_t lttng_ust_ctl_write_one_packet_to_channel(struct lttng_ust_ctl_consumer_channel *channel,
						  const char *metadata_str, /* NOT null-terminated
									     */
						  size_t len); /* metadata length */

/*
 * Send a NULL stream to finish iteration over all streams of a given
 * channel.
 */
int lttng_ust_ctl_send_stream_to_sessiond(int sock, struct lttng_ust_ctl_consumer_stream *stream);
int lttng_ust_ctl_stream_close_wait_fd(struct lttng_ust_ctl_consumer_stream *stream);
int lttng_ust_ctl_stream_close_wakeup_fd(struct lttng_ust_ctl_consumer_stream *stream);
int lttng_ust_ctl_stream_get_wait_fd(struct lttng_ust_ctl_consumer_stream *stream);
int lttng_ust_ctl_stream_get_wakeup_fd(struct lttng_ust_ctl_consumer_stream *stream);

/* Create/destroy stream buffers for read */
struct lttng_ust_ctl_consumer_stream *
lttng_ust_ctl_create_stream(struct lttng_ust_ctl_consumer_channel *channel, int cpu);
void lttng_ust_ctl_destroy_stream(struct lttng_ust_ctl_consumer_stream *stream);

/* For mmap mode, readable without "get" operation */
int lttng_ust_ctl_get_mmap_len(struct lttng_ust_ctl_consumer_stream *stream, unsigned long *len);
int lttng_ust_ctl_get_max_subbuf_size(struct lttng_ust_ctl_consumer_stream *stream,
				      unsigned long *len);

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */
void *lttng_ust_ctl_get_mmap_base(struct lttng_ust_ctl_consumer_stream *stream);
int lttng_ust_ctl_get_mmap_read_offset(struct lttng_ust_ctl_consumer_stream *stream,
				       unsigned long *off);
int lttng_ust_ctl_get_subbuf_size(struct lttng_ust_ctl_consumer_stream *stream, unsigned long *len);
int lttng_ust_ctl_get_padded_subbuf_size(struct lttng_ust_ctl_consumer_stream *stream,
					 unsigned long *len);
int lttng_ust_ctl_get_next_subbuf(struct lttng_ust_ctl_consumer_stream *stream);
int lttng_ust_ctl_put_next_subbuf(struct lttng_ust_ctl_consumer_stream *stream);

/* snapshot */

int lttng_ust_ctl_snapshot(struct lttng_ust_ctl_consumer_stream *stream);
int lttng_ust_ctl_snapshot_sample_positions(struct lttng_ust_ctl_consumer_stream *stream);
int lttng_ust_ctl_snapshot_get_consumed(struct lttng_ust_ctl_consumer_stream *stream,
					unsigned long *pos);
int lttng_ust_ctl_snapshot_get_produced(struct lttng_ust_ctl_consumer_stream *stream,
					unsigned long *pos);
int lttng_ust_ctl_get_subbuf(struct lttng_ust_ctl_consumer_stream *stream, unsigned long *pos);
int lttng_ust_ctl_put_subbuf(struct lttng_ust_ctl_consumer_stream *stream);

int lttng_ust_ctl_flush_buffer(struct lttng_ust_ctl_consumer_stream *stream, int producer_active);
int lttng_ust_ctl_clear_buffer(struct lttng_ust_ctl_consumer_stream *stream);

/* index */

/*
 * Getters which need to be used on the current packet (between get/put
 * or get_next/put_next.
 */

int lttng_ust_ctl_get_timestamp_begin(struct lttng_ust_ctl_consumer_stream *stream,
				      uint64_t *timestamp_begin);
int lttng_ust_ctl_get_timestamp_end(struct lttng_ust_ctl_consumer_stream *stream,
				    uint64_t *timestamp_end);
int lttng_ust_ctl_get_events_discarded(struct lttng_ust_ctl_consumer_stream *stream,
				       uint64_t *events_discarded);
int lttng_ust_ctl_get_content_size(struct lttng_ust_ctl_consumer_stream *stream,
				   uint64_t *content_size);
int lttng_ust_ctl_get_packet_size(struct lttng_ust_ctl_consumer_stream *stream,
				  uint64_t *packet_size);
int lttng_ust_ctl_get_sequence_number(struct lttng_ust_ctl_consumer_stream *stream, uint64_t *seq);

/*
 * Getter returning state invariant for the stream, which can be used
 * without "get" operation.
 */

int lttng_ust_ctl_get_stream_id(struct lttng_ust_ctl_consumer_stream *stream, uint64_t *stream_id);
int lttng_ust_ctl_get_instance_id(struct lttng_ust_ctl_consumer_stream *stream, uint64_t *id);

/*
 * Getter returning the current timestamp as perceived from the
 * tracer.
 */
int lttng_ust_ctl_get_current_timestamp(struct lttng_ust_ctl_consumer_stream *stream, uint64_t *ts);

/* returns whether UST has perf counters support. */
int lttng_ust_ctl_has_perf_counters(void);

/* Regenerate the statedump. */
int lttng_ust_ctl_regenerate_statedump(int sock, int handle);

/* event registry management */

enum lttng_ust_ctl_socket_type {
	LTTNG_UST_CTL_SOCKET_CMD = 0,
	LTTNG_UST_CTL_SOCKET_NOTIFY = 1,
};

enum lttng_ust_ctl_notify_cmd {
	LTTNG_UST_CTL_NOTIFY_CMD_EVENT = 0,
	LTTNG_UST_CTL_NOTIFY_CMD_CHANNEL = 1,
	LTTNG_UST_CTL_NOTIFY_CMD_ENUM = 2,
};

enum lttng_ust_ctl_channel_header {
	LTTNG_UST_CTL_CHANNEL_HEADER_UNKNOWN = 0,
	LTTNG_UST_CTL_CHANNEL_HEADER_COMPACT = 1,
	LTTNG_UST_CTL_CHANNEL_HEADER_LARGE = 2,
};

/* event type structures */

enum lttng_ust_ctl_abstract_types {
	lttng_ust_ctl_atype_integer,
	lttng_ust_ctl_atype_enum, /* legacy */
	lttng_ust_ctl_atype_array, /* legacy */
	lttng_ust_ctl_atype_sequence, /* legacy */
	lttng_ust_ctl_atype_string,
	lttng_ust_ctl_atype_float,
	lttng_ust_ctl_atype_variant, /* legacy */
	lttng_ust_ctl_atype_struct, /* legacy */
	lttng_ust_ctl_atype_enum_nestable,
	lttng_ust_ctl_atype_array_nestable,
	lttng_ust_ctl_atype_sequence_nestable,
	lttng_ust_ctl_atype_struct_nestable,
	lttng_ust_ctl_atype_variant_nestable,
	NR_LTTNG_UST_CTL_ABSTRACT_TYPES,
};

enum lttng_ust_ctl_string_encodings {
	lttng_ust_ctl_encode_none = 0,
	lttng_ust_ctl_encode_UTF8 = 1,
	lttng_ust_ctl_encode_ASCII = 2,
	NR_LTTNG_UST_CTL_STRING_ENCODINGS,
};

#define LTTNG_UST_CTL_UST_INTEGER_TYPE_PADDING 24
struct lttng_ust_ctl_integer_type {
	uint32_t size; /* in bits */
	uint32_t signedness;
	uint32_t reverse_byte_order;
	uint32_t base; /* 2, 8, 10, 16, for pretty print */
	int32_t encoding; /* enum lttng_ust_ctl_string_encodings */
	uint16_t alignment; /* in bits */
	char padding[LTTNG_UST_CTL_UST_INTEGER_TYPE_PADDING];
} LTTNG_PACKED;

#define LTTNG_UST_CTL_UST_FLOAT_TYPE_PADDING 24
struct lttng_ust_ctl_float_type {
	uint32_t exp_dig; /* exponent digits, in bits */
	uint32_t mant_dig; /* mantissa digits, in bits */
	uint32_t reverse_byte_order;
	uint16_t alignment; /* in bits */
	char padding[LTTNG_UST_CTL_UST_FLOAT_TYPE_PADDING];
} LTTNG_PACKED;

#define LTTNG_UST_CTL_UST_ENUM_VALUE_PADDING 15
struct lttng_ust_ctl_enum_value {
	uint64_t value;
	uint8_t signedness;
	char padding[LTTNG_UST_CTL_UST_ENUM_VALUE_PADDING];
} LTTNG_PACKED;

enum lttng_ust_ctl_ust_enum_entry_options {
	LTTNG_UST_CTL_UST_ENUM_ENTRY_OPTION_IS_AUTO = 1U << 0,
};

#define LTTNG_UST_CTL_UST_ENUM_ENTRY_PADDING 32
struct lttng_ust_ctl_enum_entry {
	struct lttng_ust_ctl_enum_value start, end; /* start and end are inclusive */
	char string[LTTNG_UST_ABI_SYM_NAME_LEN];
	union {
		struct {
			uint32_t options;
		} LTTNG_PACKED extra;
		char padding[LTTNG_UST_CTL_UST_ENUM_ENTRY_PADDING];
	} u;
} LTTNG_PACKED;

/* legacy */
#define LTTNG_UST_CTL_UST_BASIC_TYPE_PADDING 296
union _lttng_ust_ctl_basic_type {
	struct lttng_ust_ctl_integer_type integer;
	struct {
		char name[LTTNG_UST_ABI_SYM_NAME_LEN];
		struct lttng_ust_ctl_integer_type container_type;
		uint64_t id; /* enum ID in sessiond. */
	} enumeration;
	struct {
		int32_t encoding; /* enum lttng_ust_ctl_string_encodings */
	} string;
	struct lttng_ust_ctl_float_type _float;
	char padding[LTTNG_UST_CTL_UST_BASIC_TYPE_PADDING];
} LTTNG_PACKED;

/* legacy */
struct lttng_ust_ctl_basic_type {
	enum lttng_ust_ctl_abstract_types atype;
	union {
		union _lttng_ust_ctl_basic_type basic;
	} u;
} LTTNG_PACKED;

/*
 * Padding is derived from largest member: u.legacy.sequence which
 * contains two basic types, each with LTTNG_UST_CTL_UST_BASIC_TYPE_PADDING.
 */
#define LTTNG_UST_CTL_UST_TYPE_PADDING (2 * LTTNG_UST_CTL_UST_BASIC_TYPE_PADDING)
struct lttng_ust_ctl_type {
	enum lttng_ust_ctl_abstract_types atype;
	union {
		struct lttng_ust_ctl_integer_type integer;
		struct lttng_ust_ctl_float_type _float;
		struct {
			int32_t encoding; /* enum lttng_ust_ctl_string_encodings */
		} string;
		struct {
			char name[LTTNG_UST_ABI_SYM_NAME_LEN];
			uint64_t id; /* enum ID in sessiond. */
			/* container_type follows after this struct lttng_ust_ctl_field. */
		} enum_nestable;
		struct {
			uint32_t length; /* num. elems. */
			uint32_t alignment;
			/* elem_type follows after this struct lttng_ust_ctl_field. */
		} array_nestable;
		struct {
			char length_name[LTTNG_UST_ABI_SYM_NAME_LEN];
			uint32_t alignment; /* Alignment before elements. */
			/* elem_type follows after the length_type. */
		} sequence_nestable;
		struct {
			uint32_t nr_fields;
			uint32_t alignment;
			/* Followed by nr_fields struct lttng_ust_ctl_field. */
		} struct_nestable;
		struct {
			uint32_t nr_choices;
			char tag_name[LTTNG_UST_ABI_SYM_NAME_LEN];
			uint32_t alignment;
			/* Followed by nr_choices struct lttng_ust_ctl_field. */
		} variant_nestable;

		/* Legacy ABI */
		union {
			union _lttng_ust_ctl_basic_type basic;
			struct {
				struct lttng_ust_ctl_basic_type elem_type;
				uint32_t length; /* num. elems. */
			} array;
			struct {
				struct lttng_ust_ctl_basic_type length_type;
				struct lttng_ust_ctl_basic_type elem_type;
			} sequence;
			struct {
				uint32_t nr_fields;
				/* Followed by nr_fields struct lttng_ust_ctl_field. */
			} _struct;
			struct {
				uint32_t nr_choices;
				char tag_name[LTTNG_UST_ABI_SYM_NAME_LEN];
				/* Followed by nr_choices struct lttng_ust_ctl_field. */
			} variant;
		} legacy;
		char padding[LTTNG_UST_CTL_UST_TYPE_PADDING];
	} u;
} LTTNG_PACKED;

#define LTTNG_UST_CTL_UST_FIELD_PADDING 28
struct lttng_ust_ctl_field {
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
	struct lttng_ust_ctl_type type;
	char padding[LTTNG_UST_CTL_UST_FIELD_PADDING];
} LTTNG_PACKED;

/*
 * Returns 0 on success, negative error value on error.
 * If an error other than -LTTNG_UST_ERR_UNSUP_MAJOR is returned,
 * the output fields are not populated.
 */
int lttng_ust_ctl_recv_reg_msg(int sock,
			       enum lttng_ust_ctl_socket_type *type,
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
			       char *name); /* size LTTNG_UST_ABI_PROCNAME_LEN */

/*
 * Returns 0 on success, negative UST or system error value on error.
 * Receive the notification command. The "notify_cmd" can then be used
 * by the caller to find out which lttng_ust_ctl_recv_* function should be
 * called to receive the notification, and which lttng_ust_ctl_reply_* is
 * appropriate.
 */
int lttng_ust_ctl_recv_notify(int sock, enum lttng_ust_ctl_notify_cmd *notify_cmd);

/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int lttng_ust_ctl_recv_register_event(int sock,
				      int *session_objd, /* session descriptor (output) */
				      int *channel_objd, /* channel descriptor (output) */
				      char *event_name, /*
							 * event name (output,
							 * size LTTNG_UST_ABI_SYM_NAME_LEN)
							 */
				      int *loglevel,
				      char **signature, /*
							 * event signature
							 * (output, dynamically
							 * allocated, must be free(3)'d
							 * by the caller if function
							 * returns success.)
							 */
				      size_t *nr_fields,
				      struct lttng_ust_ctl_field **fields,
				      char **model_emf_uri);

/*
 * Returns 0 on success, negative error value on error.
 */
int lttng_ust_ctl_reply_register_event(int sock,
				       uint32_t id, /* event id (input) */
				       int ret_code); /* return code. 0 ok, negative error */

/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int lttng_ust_ctl_recv_register_enum(int sock,
				     int *session_objd,
				     char *enum_name,
				     struct lttng_ust_ctl_enum_entry **entries,
				     size_t *nr_entries);

/*
 * Returns 0 on success, negative error value on error.
 */
int lttng_ust_ctl_reply_register_enum(int sock,
				      uint64_t id, /* enum id (input) */
				      int ret_code);

/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int lttng_ust_ctl_recv_register_channel(int sock,
					int *session_objd, /* session descriptor (output) */
					int *channel_objd, /* channel descriptor (output) */
					size_t *nr_fields, /* context fields */
					struct lttng_ust_ctl_field **fields);

/*
 * Returns 0 on success, negative error value on error.
 */
int lttng_ust_ctl_reply_register_channel(int sock,
					 uint32_t chan_id,
					 enum lttng_ust_ctl_channel_header header_type,
					 int ret_code); /* return code. 0 ok, negative error */

/*
 * Counter API.
 */

enum lttng_ust_ctl_counter_bitness {
	LTTNG_UST_CTL_COUNTER_BITNESS_32 = 0,
	LTTNG_UST_CTL_COUNTER_BITNESS_64 = 1,
};

enum lttng_ust_ctl_counter_arithmetic {
	LTTNG_UST_CTL_COUNTER_ARITHMETIC_MODULAR = 0,
	LTTNG_UST_CTL_COUNTER_ARITHMETIC_SATURATION = 1,
};

/* Used as alloc flags. */
enum lttng_ust_ctl_counter_alloc {
	LTTNG_UST_CTL_COUNTER_ALLOC_PER_CPU = (1 << 0),
	LTTNG_UST_CTL_COUNTER_ALLOC_GLOBAL = (1 << 1),
};

struct lttng_ust_ctl_daemon_counter;

int lttng_ust_ctl_get_nr_cpu_per_counter(void);

struct lttng_ust_ctl_counter_dimension {
	uint64_t size;
	uint64_t underflow_index;
	uint64_t overflow_index;
	uint8_t has_underflow;
	uint8_t has_overflow;
};

struct lttng_ust_ctl_daemon_counter *
lttng_ust_ctl_create_counter(size_t nr_dimensions,
			     const struct lttng_ust_ctl_counter_dimension *dimensions,
			     int64_t global_sum_step,
			     int global_counter_fd,
			     int nr_counter_cpu_fds,
			     const int *counter_cpu_fds,
			     enum lttng_ust_ctl_counter_bitness bitness,
			     enum lttng_ust_ctl_counter_arithmetic arithmetic,
			     uint32_t alloc_flags,
			     bool coalesce_hits);

int lttng_ust_ctl_create_counter_data(struct lttng_ust_ctl_daemon_counter *counter,
				      struct lttng_ust_abi_object_data **counter_data);

int lttng_ust_ctl_create_counter_global_data(struct lttng_ust_ctl_daemon_counter *counter,
					     struct lttng_ust_abi_object_data **counter_global_data);
int lttng_ust_ctl_create_counter_cpu_data(struct lttng_ust_ctl_daemon_counter *counter,
					  int cpu,
					  struct lttng_ust_abi_object_data **counter_cpu_data);

/*
 * Each counter data and counter cpu data created need to be destroyed
 * before calling lttng_ust_ctl_destroy_counter().
 */
void lttng_ust_ctl_destroy_counter(struct lttng_ust_ctl_daemon_counter *counter);

int lttng_ust_ctl_send_counter_data_to_ust(int sock,
					   int parent_handle,
					   struct lttng_ust_abi_object_data *counter_data);
int lttng_ust_ctl_send_counter_global_data_to_ust(
	int sock,
	struct lttng_ust_abi_object_data *counter_data,
	struct lttng_ust_abi_object_data *counter_global_data);
int lttng_ust_ctl_send_counter_cpu_data_to_ust(int sock,
					       struct lttng_ust_abi_object_data *counter_data,
					       struct lttng_ust_abi_object_data *counter_cpu_data);

int lttng_ust_ctl_counter_read(struct lttng_ust_ctl_daemon_counter *counter,
			       const size_t *dimension_indexes,
			       int cpu,
			       int64_t *value,
			       bool *overflow,
			       bool *underflow);
int lttng_ust_ctl_counter_aggregate(struct lttng_ust_ctl_daemon_counter *counter,
				    const size_t *dimension_indexes,
				    int64_t *value,
				    bool *overflow,
				    bool *underflow);
int lttng_ust_ctl_counter_clear(struct lttng_ust_ctl_daemon_counter *counter,
				const size_t *dimension_indexes);

void lttng_ust_ctl_sigbus_handle(void *addr);

#endif /* LTTNG_UST_CTL_INTERNAL_H */
