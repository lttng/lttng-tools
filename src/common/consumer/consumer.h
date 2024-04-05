/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LIB_CONSUMER_H
#define LIB_CONSUMER_H

#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <unistd.h>
#include <urcu/list.h>

#include <lttng/lttng.h>

#include <common/hashtable/hashtable.h>
#include <common/compat/fcntl.h>
#include <common/uuid.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/pipe.h>
#include <common/index/ctf-index.h>
#include <common/trace-chunk-registry.h>
#include <common/credentials.h>
#include <common/buffer-view.h>
#include <common/dynamic-array.h>
#include <common/waiter.h>

struct lttng_consumer_local_data;

/* Commands for consumer */
enum lttng_consumer_command {
	LTTNG_CONSUMER_ADD_CHANNEL,
	LTTNG_CONSUMER_ADD_STREAM,
	/* pause, delete, active depending on fd state */
	LTTNG_CONSUMER_UPDATE_STREAM,
	/* inform the consumer to quit when all fd has hang up */
	LTTNG_CONSUMER_STOP,	/* deprecated */
	LTTNG_CONSUMER_ADD_RELAYD_SOCKET,
	/* Inform the consumer to kill a specific relayd connection */
	LTTNG_CONSUMER_DESTROY_RELAYD,
	/* Return to the sessiond if there is data pending for a session */
	LTTNG_CONSUMER_DATA_PENDING,
	/* Consumer creates a channel and returns it to sessiond. */
	LTTNG_CONSUMER_ASK_CHANNEL_CREATION,
	LTTNG_CONSUMER_GET_CHANNEL,
	LTTNG_CONSUMER_DESTROY_CHANNEL,
	LTTNG_CONSUMER_PUSH_METADATA,
	LTTNG_CONSUMER_CLOSE_METADATA,
	LTTNG_CONSUMER_SETUP_METADATA,
	LTTNG_CONSUMER_FLUSH_CHANNEL,
	LTTNG_CONSUMER_SNAPSHOT_CHANNEL,
	LTTNG_CONSUMER_SNAPSHOT_METADATA,
	LTTNG_CONSUMER_STREAMS_SENT,
	LTTNG_CONSUMER_DISCARDED_EVENTS,
	LTTNG_CONSUMER_LOST_PACKETS,
	LTTNG_CONSUMER_CLEAR_QUIESCENT_CHANNEL,
	LTTNG_CONSUMER_SET_CHANNEL_MONITOR_PIPE,
	LTTNG_CONSUMER_ROTATE_CHANNEL,
	LTTNG_CONSUMER_INIT,
	LTTNG_CONSUMER_CREATE_TRACE_CHUNK,
	LTTNG_CONSUMER_CLOSE_TRACE_CHUNK,
	LTTNG_CONSUMER_TRACE_CHUNK_EXISTS,
	LTTNG_CONSUMER_CLEAR_CHANNEL,
	LTTNG_CONSUMER_OPEN_CHANNEL_PACKETS,
};

enum lttng_consumer_type {
	LTTNG_CONSUMER_UNKNOWN = 0,
	LTTNG_CONSUMER_KERNEL,
	LTTNG_CONSUMER64_UST,
	LTTNG_CONSUMER32_UST,
};

enum consumer_endpoint_status {
	CONSUMER_ENDPOINT_ACTIVE,
	CONSUMER_ENDPOINT_INACTIVE,
};

enum consumer_channel_output {
	CONSUMER_CHANNEL_MMAP	= 0,
	CONSUMER_CHANNEL_SPLICE	= 1,
};

enum consumer_channel_type {
	CONSUMER_CHANNEL_TYPE_METADATA	= 0,
	CONSUMER_CHANNEL_TYPE_DATA	= 1,
};

enum sync_metadata_status {
	SYNC_METADATA_STATUS_NEW_DATA,
	SYNC_METADATA_STATUS_NO_DATA,
	SYNC_METADATA_STATUS_ERROR,
};

extern struct lttng_consumer_global_data the_consumer_data;

struct stream_list {
	struct cds_list_head head;
	unsigned int count;
};

/* Stub. */
struct consumer_metadata_cache;

struct lttng_consumer_channel {
	/* Is the channel published in the channel hash tables? */
	bool is_published;
	/*
	 * Was the channel deleted (logically) and waiting to be reclaimed?
	 * If this flag is set, no modification that is not cleaned-up by the
	 * RCU reclamation callback should be made
	 */
	bool is_deleted;
	/* HT node used for consumer_data.channel_ht */
	struct lttng_ht_node_u64 node;
	/* HT node used for consumer_data.channels_by_session_id_ht */
	struct lttng_ht_node_u64 channels_by_session_id_ht_node;
	/* Indexed key. Incremented value in the consumer. */
	uint64_t key;
	/* Number of streams referencing this channel */
	int refcount;
	/* Tracing session id on the session daemon side. */
	uint64_t session_id;
	/* Current trace chunk of the session in which this channel exists. */
	struct lttng_trace_chunk *trace_chunk;
	/*
	 * Session id when requesting metadata to the session daemon for
	 * a session with per-PID buffers.
	 */
	uint64_t session_id_per_pid;
	/*
	 * In the case of local streams, this field contains the channel's
	 * output path; a path relative to the session's output path.
	 *   e.g. ust/uid/1000/64-bit
	 *
	 * In the case of remote streams, the contents of this field depends
	 * on the version of the relay daemon peer. For 2.11+ peers, the
	 * contents are the same as in the local case. However, for legacy
	 * peers, this contains a path of the form:
	 *   /hostname/session_path/ust/uid/1000/64-bit
	 */
	char pathname[PATH_MAX];
	/* Channel name. */
	char name[LTTNG_SYMBOL_NAME_LEN];
	/* Relayd id of the channel. -1ULL if it does not apply. */
	uint64_t relayd_id;
	/*
	 * Number of streams NOT initialized yet. This is used in order to not
	 * delete this channel if streams are getting initialized.
	 */
	unsigned int nb_init_stream_left;
	/* Output type (mmap or splice). */
	enum consumer_channel_output output;
	/* Channel type for stream */
	enum consumer_channel_type type;

	/* For UST */
	uid_t ust_app_uid;	/* Application UID. */
	struct lttng_ust_ctl_consumer_channel *uchan;
	unsigned char uuid[LTTNG_UUID_STR_LEN];
	/*
	 * Temporary stream list used to store the streams once created and waiting
	 * to be sent to the session daemon by receiving the
	 * LTTNG_CONSUMER_GET_CHANNEL.
	 */
	struct stream_list streams;

	/*
	 * Set if the channel is metadata. We keep a reference to the stream
	 * because we have to flush data once pushed by the session daemon. For a
	 * regular channel, this is always set to NULL.
	 */
	struct lttng_consumer_stream *metadata_stream;

	/* for UST */
	int wait_fd;
	/* Node within channel thread ht */
	struct lttng_ht_node_u64 wait_fd_node;

	/* Metadata cache is metadata channel */
	struct consumer_metadata_cache *metadata_cache;

	/*
	 * Wait queue awaiting updates to metadata stream's flushed position.
	 */
	struct lttng_wait_queue metadata_pushed_wait_queue;

	/* For UST metadata periodical flush */
	int switch_timer_enabled;
	timer_t switch_timer;
	int switch_timer_error;

	/* For the live mode */
	int live_timer_enabled;
	timer_t live_timer;
	int live_timer_error;
	/* Channel is part of a live session ? */
	bool is_live;

	/* For channel monitoring timer. */
	int monitor_timer_enabled;
	timer_t monitor_timer;

	/* On-disk circular buffer */
	uint64_t tracefile_size;
	uint64_t tracefile_count;
	/*
	 * Monitor or not the streams of this channel meaning this indicates if the
	 * streams should be sent to the data/metadata thread or added to the no
	 * monitor list of the channel.
	 */
	unsigned int monitor;

	/*
	 * Channel lock.
	 *
	 * This lock protects against concurrent update of channel.
	 *
	 * This is nested INSIDE the consumer data lock.
	 * This is nested OUTSIDE the channel timer lock.
	 * This is nested OUTSIDE the metadata cache lock.
	 * This is nested OUTSIDE stream lock.
	 * This is nested OUTSIDE consumer_relayd_sock_pair lock.
	 */
	pthread_mutex_t lock;

	/*
	 * Channel teardown lock.
	 *
	 * This lock protect against teardown of channel. It is _never_
	 * taken by the timer handler.
	 *
	 * This is nested INSIDE the consumer data lock.
	 * This is nested INSIDE the channel lock.
	 * This is nested OUTSIDE the metadata cache lock.
	 * This is nested OUTSIDE stream lock.
	 * This is nested OUTSIDE consumer_relayd_sock_pair lock.
	 */
	pthread_mutex_t timer_lock;

	/* Timer value in usec for live streaming. */
	unsigned int live_timer_interval;

	int *stream_fds;
	int nr_stream_fds;
	char root_shm_path[PATH_MAX];
	char shm_path[PATH_MAX];
	/* Only set for UST channels. */
	LTTNG_OPTIONAL(struct lttng_credentials) buffer_credentials;
	/* Total number of discarded events for that channel. */
	uint64_t discarded_events;
	/* Total number of missed packets due to overwriting (overwrite). */
	uint64_t lost_packets;

	bool streams_sent_to_relayd;
};

struct stream_subbuffer {
	union {
		/*
		 * CONSUMER_CHANNEL_SPLICE
		 * No ownership assumed.
		 */
		int fd;
		/* CONSUMER_CHANNEL_MMAP */
		struct lttng_buffer_view buffer;
	} buffer;
	union {
		/*
		 * Common members are fine to access through either
		 * union entries (as per C11, Common Initial Sequence).
		 */
		struct {
			unsigned long subbuf_size;
			unsigned long padded_subbuf_size;
			uint64_t version;
			/*
			 * Left unset when unsupported.
			 *
			 * Indicates that this is the last sub-buffer of
			 * a series of sub-buffer that makes-up a coherent
			 * (parseable) unit of metadata.
			 */
			LTTNG_OPTIONAL(bool) coherent;
		} metadata;
		struct {
			unsigned long subbuf_size;
			unsigned long padded_subbuf_size;
			uint64_t packet_size;
			uint64_t content_size;
			uint64_t timestamp_begin;
			uint64_t timestamp_end;
			uint64_t events_discarded;
			/* Left unset when unsupported. */
			LTTNG_OPTIONAL(uint64_t) sequence_number;
			uint64_t stream_id;
			/* Left unset when unsupported. */
			LTTNG_OPTIONAL(uint64_t) stream_instance_id;
		} data;
	} info;
};

enum get_next_subbuffer_status {
	GET_NEXT_SUBBUFFER_STATUS_OK,
	GET_NEXT_SUBBUFFER_STATUS_NO_DATA,
	GET_NEXT_SUBBUFFER_STATUS_ERROR,
};

/*
 * Perform any operation required to acknowledge
 * the wake-up of a consumer stream (e.g. consume a byte on a wake-up pipe).
 *
 * Stream and channel locks are acquired during this call.
 */
typedef int (*on_wake_up_cb)(struct lttng_consumer_stream *);

/*
 * Perform any operation required before a consumer stream is put
 * to sleep before awaiting a data availability notification.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef int (*on_sleep_cb)(struct lttng_consumer_stream *,
		struct lttng_consumer_local_data *);

/*
 * Acquire the subbuffer at the current 'consumed' position.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef enum get_next_subbuffer_status (*get_next_subbuffer_cb)(
		struct lttng_consumer_stream *, struct stream_subbuffer *);

/*
 * Populate the stream_subbuffer's info member. The info to populate
 * depends on the type (metadata/data) of the stream.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef int (*extract_subbuffer_info_cb)(
		struct lttng_consumer_stream *, struct stream_subbuffer *);

/*
 * Invoked after a subbuffer's info has been filled.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef int (*pre_consume_subbuffer_cb)(struct lttng_consumer_stream *,
		const struct stream_subbuffer *);

/*
 * Consume subbuffer contents.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef ssize_t (*consume_subbuffer_cb)(struct lttng_consumer_local_data *,
		struct lttng_consumer_stream *,
		const struct stream_subbuffer *);

/*
 * Release the current subbuffer and advance the 'consumed' position by
 * one subbuffer.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef int (*put_next_subbuffer_cb)(struct lttng_consumer_stream *,
		struct stream_subbuffer *);

/*
 * Invoked after consuming a subbuffer.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef int (*post_consume_cb)(struct lttng_consumer_stream *,
		const struct stream_subbuffer *,
		struct lttng_consumer_local_data *);

/*
 * Send a live beacon if no data is available.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef int (*send_live_beacon_cb)(struct lttng_consumer_stream *);

/*
 * Lock the stream and channel locks and any other stream-type specific
 * lock that need to be acquired during the processing of an
 * availability notification.
 */
typedef void (*lock_cb)(struct lttng_consumer_stream *);

/*
 * Unlock the stream and channel locks and any other stream-type specific
 * lock before sleeping until the next availability notification.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef void (*unlock_cb)(struct lttng_consumer_stream *);

/*
 * Assert that the stream and channel lock and any other stream type specific
 * lock that need to be acquired during the processing of a read_subbuffer
 * operation is acquired.
 */
typedef void (*assert_locked_cb)(struct lttng_consumer_stream *);

/*
 * Invoked when a subbuffer's metadata version does not match the last
 * known metadata version.
 *
 * Stream and channel locks are acquired during this call.
 */
typedef void (*reset_metadata_cb)(struct lttng_consumer_stream *);

/*
 * Internal representation of the streams, sessiond_key is used to identify
 * uniquely a stream.
 */
struct lttng_consumer_stream {
	/* HT node used by the data_ht and metadata_ht */
	struct lttng_ht_node_u64 node;
	/* stream indexed per channel key node */
	struct lttng_ht_node_u64 node_channel_id;
	/* HT node used in consumer_data.stream_list_ht */
	struct lttng_ht_node_u64 node_session_id;
	/*
	 * List used by channels to reference streams that are not yet globally
	 * visible.
	 */
	struct cds_list_head send_node;
	/* Pointer to associated channel. */
	struct lttng_consumer_channel *chan;
	/*
	 * Current trace chunk. Holds a reference to the trace chunk.
	 * `chunk` can be NULL when a stream is not associated to a chunk, e.g.
	 * when it was created in the context of a no-output session.
	 */
	struct lttng_trace_chunk *trace_chunk;

	/* Key by which the stream is indexed for 'node'. */
	uint64_t key;
	/*
	 * File descriptor of the data output file. This can be either a file or a
	 * socket fd for relayd streaming.
	 */
	int out_fd; /* output file to write the data */
	/* Write position in the output file descriptor */
	off_t out_fd_offset;
	/* Amount of bytes written to the output */
	uint64_t output_written;
	int shm_fd_is_copy;
	int data_read;
	int hangup_flush_done;

	/*
	 * Whether the stream is in a "complete" state (e.g. it does not have a
	 * partially written sub-buffer.
	 *
	 * Initialized to "false" on stream creation (first packet is empty).
	 *
	 * The various transitions of the quiescent state are:
	 *     - On "start" tracing: set to false, since the stream is not
	 *       "complete".
	 *     - On "stop" tracing: if !quiescent -> flush FINAL (update
	 *       timestamp_end), and set to true; the stream has entered a
	 *       complete/quiescent state.
	 *     - On "destroy" or stream/application hang-up: if !quiescent ->
	 *       flush FINAL, and set to true.
	 *
	 * NOTE: Update and read are protected by the stream lock.
	 */
	bool quiescent;

	/*
	 * True if the sequence number is not available (lttng-modules < 2.8).
	 */
	bool sequence_number_unavailable;

	/*
	 * metadata_timer_lock protects flags waiting_on_metadata and
	 * missed_metadata_flush.
	 */
	pthread_mutex_t metadata_timer_lock;
	/*
	 * Flag set when awaiting metadata to be pushed. Used in the
	 * timer thread to skip waiting on the stream (and stream lock) to
	 * ensure we can proceed to flushing metadata in live mode.
	 */
	bool waiting_on_metadata;
	/* Raised when a timer misses a metadata flush. */
	bool missed_metadata_flush;

	enum lttng_event_output output;
	/* Maximum subbuffer size (in bytes). */
	unsigned long max_sb_size;

	/*
	 * Still used by the kernel for MMAP output. For UST, the ustctl getter is
	 * used for the mmap base and offset.
	 */
	void *mmap_base;
	unsigned long mmap_len;

	/* For UST */

	int wait_fd;
	/* Network sequence number. Indicating on which relayd socket it goes. */
	uint64_t net_seq_idx;
	/*
	 * Indicate if this stream was successfully sent to a relayd. This is set
	 * after the refcount of the relayd is incremented and is checked when the
	 * stream is closed before decrementing the refcount in order to avoid an
	 * unbalanced state.
	 */
	unsigned int sent_to_relayd;

	/* Identify if the stream is the metadata */
	unsigned int metadata_flag;
	/*
	 * Last known metadata version, reset the metadata file in case
	 * of change.
	 */
	uint64_t metadata_version;
	/* Used when the stream is set for network streaming */
	uint64_t relayd_stream_id;
	/*
	 * When sending a stream packet to a relayd, this number is used to track
	 * the packet sent by the consumer and seen by the relayd. When sending the
	 * data header to the relayd, this number is sent and if the transmission
	 * was successful, it is incremented.
	 *
	 * Even if the full data is not fully transmitted it won't matter since
	 * only two possible error can happen after that where either the relayd
	 * died or a read error is detected on the stream making this value useless
	 * after that.
	 *
	 * This value SHOULD be read/updated atomically or with the lock acquired.
	 */
	uint64_t next_net_seq_num;
	/*
	 * Lock to use the stream FDs since they are used between threads.
	 *
	 * This is nested INSIDE the consumer_data lock.
	 * This is nested INSIDE the channel lock.
	 * This is nested INSIDE the channel timer lock.
	 * This is nested OUTSIDE the metadata cache lock.
	 * This is nested OUTSIDE consumer_relayd_sock_pair lock.
	 */
	pthread_mutex_t lock;
	/* Tracing session id */
	uint64_t session_id;
	/*
	 * Indicates if the stream end point is still active or not (network
	 * streaming or local file system). The thread "owning" the stream is
	 * handling this status and can be notified of a state change through the
	 * consumer data appropriate pipe.
	 */
	enum consumer_endpoint_status endpoint_status;
	/* Stream name. Format is: <channel_name>_<cpu_number> */
	char name[LTTNG_SYMBOL_NAME_LEN];
	/* Internal state of libustctl. */
	struct lttng_ust_ctl_consumer_stream *ustream;
	/* On-disk circular buffer */
	uint64_t tracefile_size_current;
	uint64_t tracefile_count_current;
	/*
	 * Monitor or not the streams of this channel meaning this indicates if the
	 * streams should be sent to the data/metadata thread or added to the no
	 * monitor list of the channel.
	 */
	unsigned int monitor;
	/*
	 * Indicate if the stream is globally visible meaning that it has been
	 * added to the multiple hash tables. If *not* set, NO lock should be
	 * acquired in the destroy path.
	 */
	unsigned int globally_visible;
	/*
	 * Pipe to wake up the metadata poll thread when the UST metadata
	 * cache is updated.
	 */
	int ust_metadata_poll_pipe[2];
	/*
	 * How much metadata was read from the metadata cache and sent
	 * to the channel.
	 */
	uint64_t ust_metadata_pushed;
	/*
	 * Copy of the last discarded event value to detect the overflow of
	 * the counter.
	 */
	uint64_t last_discarded_events;
	/* Copy of the sequence number of the last packet extracted. */
	uint64_t last_sequence_number;
	/*
	 * Index file object of the index file for this stream.
	 */
	struct lttng_index_file *index_file;

	/*
	 * Local pipe to extract data when using splice.
	 */
	int splice_pipe[2];

	/*
	 * Rendez-vous point between data and metadata stream in live mode.
	 */
	pthread_cond_t metadata_rdv;
	pthread_mutex_t metadata_rdv_lock;

	/*
	 * rotate_position represents the packet sequence number of the last
	 * packet which belongs to the current trace chunk prior to the rotation.
	 * When that position is reached, this tracefile can be closed and a
	 * new one is created in channel_read_only_attributes.path.
	 */
	uint64_t rotate_position;

	/* Whether or not a packet was opened during the current trace chunk. */
	bool opened_packet_in_current_trace_chunk;

	/*
	 * Read-only copies of channel values. We cannot safely access the
	 * channel from a stream, so we need to have a local copy of these
	 * fields in the stream object. These fields should be removed from
	 * the stream objects when we introduce refcounting.
	 */
	struct {
		uint64_t tracefile_size;
	} channel_read_only_attributes;

	/*
	 * Flag to inform the data or metadata thread that a stream is
	 * ready to be rotated.
	 */
	bool rotate_ready;

	/* Indicate if the stream still has some data to be read. */
	unsigned int has_data:1;
	/*
	 * Inform the consumer or relay to reset the metadata
	 * file before writing in it (regeneration).
	 */
	unsigned int reset_metadata_flag:1;
	struct {
		/*
		 * Invoked in the order of declaration.
		 * See callback type definitions.
		 */
		lock_cb lock;
		on_wake_up_cb on_wake_up;
		get_next_subbuffer_cb get_next_subbuffer;
		extract_subbuffer_info_cb extract_subbuffer_info;
		pre_consume_subbuffer_cb pre_consume_subbuffer;
		reset_metadata_cb reset_metadata;
		consume_subbuffer_cb consume_subbuffer;
		put_next_subbuffer_cb put_next_subbuffer;
		struct lttng_dynamic_array post_consume_cbs;
		send_live_beacon_cb send_live_beacon;
		on_sleep_cb on_sleep;
		unlock_cb unlock;
		assert_locked_cb assert_locked;
	} read_subbuffer_ops;
	struct metadata_bucket *metadata_bucket;
};

/*
 * Internal representation of a relayd socket pair.
 */
struct consumer_relayd_sock_pair {
	/* Network sequence number. */
	uint64_t net_seq_idx;
	/* Number of stream associated with this relayd */
	int refcount;

	/*
	 * This flag indicates whether or not we should destroy this object. The
	 * destruction should ONLY occurs when this flag is set and the refcount is
	 * set to zero.
	 */
	unsigned int destroy_flag;

	/*
	 * Mutex protecting the control socket to avoid out of order packets
	 * between threads sending data to the relayd. Since metadata data is sent
	 * over that socket, at least two sendmsg() are needed (header + data)
	 * creating a race for packets to overlap between threads using it.
	 *
	 * This is nested INSIDE the consumer_data lock.
	 * This is nested INSIDE the stream lock.
	 */
	pthread_mutex_t ctrl_sock_mutex;

	/* Control socket. Command and metadata are passed over it */
	struct lttcomm_relayd_sock control_sock;

	/*
	 * We don't need a mutex at this point since we only splice or write single
	 * large chunk of data with a header appended at the begining. Moreover,
	 * this socket is for now only used in a single thread.
	 */
	struct lttcomm_relayd_sock data_sock;
	struct lttng_ht_node_u64 node;

	/* Session id on both sides for the sockets. */
	uint64_t relayd_session_id;
	uint64_t sessiond_session_id;
	struct lttng_consumer_local_data *ctx;
};

/*
 * UST consumer local data to the program. One or more instance per
 * process.
 */
struct lttng_consumer_local_data {
	/*
	 * Function to call when data is available on a buffer.
	 * Returns the number of bytes read, or negative error value.
	 */
	ssize_t (*on_buffer_ready)(struct lttng_consumer_stream *stream,
			struct lttng_consumer_local_data *ctx,
			bool locked_by_caller);
	/*
	 * function to call when we receive a new channel, it receives a
	 * newly allocated channel, depending on the return code of this
	 * function, the new channel will be handled by the application
	 * or the library.
	 *
	 * Returns:
	 *    > 0 (success, FD is kept by application)
	 *   == 0 (success, FD is left to library)
	 *    < 0 (error)
	 */
	int (*on_recv_channel)(struct lttng_consumer_channel *channel);
	/*
	 * function to call when we receive a new stream, it receives a
	 * newly allocated stream, depending on the return code of this
	 * function, the new stream will be handled by the application
	 * or the library.
	 *
	 * Returns:
	 *    > 0 (success, FD is kept by application)
	 *   == 0 (success, FD is left to library)
	 *    < 0 (error)
	 */
	int (*on_recv_stream)(struct lttng_consumer_stream *stream);
	/*
	 * function to call when a stream is getting updated by the session
	 * daemon, this function receives the sessiond key and the new
	 * state, depending on the return code of this function the
	 * update of state for the stream is handled by the application
	 * or the library.
	 *
	 * Returns:
	 *    > 0 (success, FD is kept by application)
	 *   == 0 (success, FD is left to library)
	 *    < 0 (error)
	 */
	int (*on_update_stream)(uint64_t sessiond_key, uint32_t state);
	enum lttng_consumer_type type;
	/* socket to communicate errors with sessiond */
	int consumer_error_socket;
	/* socket to ask metadata to sessiond. */
	int consumer_metadata_socket;
	/*
	 * Protect consumer_metadata_socket.
	 *
	 * This is nested OUTSIDE the metadata cache lock.
	 */
	pthread_mutex_t metadata_socket_lock;
	/* socket to exchange commands with sessiond */
	char *consumer_command_sock_path;
	/* communication with splice */
	int consumer_channel_pipe[2];
	/* Data stream poll thread pipe. To transfer data stream to the thread */
	struct lttng_pipe *consumer_data_pipe;

	/*
	 * Data thread use that pipe to catch wakeup from read subbuffer that
	 * detects that there is still data to be read for the stream encountered.
	 * Before doing so, the stream is flagged to indicate that there is still
	 * data to be read.
	 *
	 * Both pipes (read/write) are owned and used inside the data thread.
	 */
	struct lttng_pipe *consumer_wakeup_pipe;
	/* Indicate if the wakeup thread has been notified. */
	unsigned int has_wakeup:1;

	/* to let the signal handler wake up the fd receiver thread */
	int consumer_should_quit[2];
	/* Metadata poll thread pipe. Transfer metadata stream to it */
	struct lttng_pipe *consumer_metadata_pipe;
	/*
	 * Pipe used by the channel monitoring timers to provide state samples
	 * to the session daemon (write-only).
	 */
	int channel_monitor_pipe;
	LTTNG_OPTIONAL(lttng_uuid) sessiond_uuid;
};

/*
 * Library-level data. One instance per process.
 */
struct lttng_consumer_global_data {
	/*
	 * At this time, this lock is used to ensure coherence between the count
	 * and number of element in the hash table. It's also a protection for
	 * concurrent read/write between threads.
	 *
	 * This is nested OUTSIDE the stream lock.
	 * This is nested OUTSIDE the consumer_relayd_sock_pair lock.
	 */
	pthread_mutex_t lock;

	/*
	 * Number of streams in the data stream hash table declared outside.
	 * Protected by consumer_data.lock.
	 */
	int stream_count;

	/* Channel hash table protected by consumer_data.lock. */
	struct lttng_ht *channel_ht;
	/* Channel hash table indexed by session id. */
	struct lttng_ht *channels_by_session_id_ht;
	/*
	 * Flag specifying if the local array of FDs needs update in the
	 * poll function. Protected by consumer_data.lock.
	 */
	unsigned int need_update;
	enum lttng_consumer_type type;

	/*
	 * Relayd socket(s) hashtable indexed by network sequence number. Each
	 * stream has an index which associate the right relayd socket to use.
	 */
	struct lttng_ht *relayd_ht;

	/*
	 * This hash table contains all streams (metadata and data) indexed by
	 * session id. In other words, the ht is indexed by session id and each
	 * bucket contains the list of associated streams.
	 *
	 * This HT uses the "node_session_id" of the consumer stream.
	 */
	struct lttng_ht *stream_list_ht;

	/*
	 * This HT uses the "node_channel_id" of the consumer stream.
	 */
	struct lttng_ht *stream_per_chan_id_ht;

	/*
	 * Trace chunk registry indexed by (session_id, chunk_id).
	 */
	struct lttng_trace_chunk_registry *chunk_registry;
};

/*
 * Set to nonzero when the consumer is exiting. Updated by signal
 * handler and thread exit, read by threads.
 */
extern int consumer_quit;

/*
 * Set to nonzero when the consumer is exiting. Updated by signal
 * handler and thread exit, read by threads.
 */
extern int consumer_quit;

/* Flag used to temporarily pause data consumption from testpoints. */
extern int data_consumption_paused;

/* Return a human-readable consumer type string that is suitable for logging. */
static inline
const char *lttng_consumer_type_str(enum lttng_consumer_type type)
{
	switch (type) {
	case LTTNG_CONSUMER_UNKNOWN:
		return "unknown";
	case LTTNG_CONSUMER_KERNEL:
		return "kernel";
	case LTTNG_CONSUMER32_UST:
		return "32-bit user space";
	case LTTNG_CONSUMER64_UST:
		return "64-bit user space";
	default:
		abort();
	}
}

/*
 * Init consumer data structures.
 */
int lttng_consumer_init(void);

/*
 * Set the error socket for communication with a session daemon.
 */
void lttng_consumer_set_error_sock(struct lttng_consumer_local_data *ctx,
		int sock);

/*
 * Set the command socket path for communication with a session daemon.
 */
void lttng_consumer_set_command_sock_path(
		struct lttng_consumer_local_data *ctx, char *sock);

/*
 * Send return code to session daemon.
 *
 * Returns the return code of sendmsg : the number of bytes transmitted or -1
 * on error.
 */
int lttng_consumer_send_error(struct lttng_consumer_local_data *ctx,
		enum lttcomm_return_code error_code);

/*
 * Called from signal handler to ensure a clean exit.
 */
void lttng_consumer_should_exit(struct lttng_consumer_local_data *ctx);

/*
 * Cleanup the daemon's socket on exit.
 */
void lttng_consumer_cleanup(void);

/*
 * Poll on the should_quit pipe and the command socket return -1 on error and
 * should exit, 0 if data is available on the command socket
 */
int lttng_consumer_poll_socket(struct pollfd *kconsumer_sockpoll);

/*
 * Copy the fields from the channel that need to be accessed (read-only)
 * directly from the stream.
 */
void consumer_stream_update_channel_attributes(
		struct lttng_consumer_stream *stream,
		struct lttng_consumer_channel *channel);

struct lttng_consumer_stream *consumer_allocate_stream(
		struct lttng_consumer_channel *channel,
		uint64_t channel_key,
		uint64_t stream_key,
		const char *channel_name,
		uint64_t relayd_id,
		uint64_t session_id,
		struct lttng_trace_chunk *trace_chunk,
		int cpu,
		int *alloc_ret,
		enum consumer_channel_type type,
		unsigned int monitor);
struct lttng_consumer_channel *consumer_allocate_channel(uint64_t key,
		uint64_t session_id,
		const uint64_t *chunk_id,
		const char *pathname,
		const char *name,
		uint64_t relayd_id,
		enum lttng_event_output output,
		uint64_t tracefile_size,
		uint64_t tracefile_count,
		uint64_t session_id_per_pid,
		unsigned int monitor,
		unsigned int live_timer_interval,
		bool is_in_live_session,
		const char *root_shm_path,
		const char *shm_path);
void consumer_del_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht);
void consumer_del_metadata_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht);
int consumer_add_channel(struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx);
void consumer_del_channel(struct lttng_consumer_channel *channel);

/* lttng-relayd consumer command */
struct consumer_relayd_sock_pair *consumer_find_relayd(uint64_t key);
int consumer_send_relayd_stream(struct lttng_consumer_stream *stream, char *path);
int consumer_send_relayd_streams_sent(uint64_t net_seq_idx);
void close_relayd_stream(struct lttng_consumer_stream *stream);
struct lttng_consumer_channel *consumer_find_channel(uint64_t key);
int consumer_handle_stream_before_relayd(struct lttng_consumer_stream *stream,
		size_t data_size);
void consumer_steal_stream_key(int key, struct lttng_ht *ht);

struct lttng_consumer_local_data *lttng_consumer_create(
		enum lttng_consumer_type type,
		ssize_t (*buffer_ready)(struct lttng_consumer_stream *stream,
			struct lttng_consumer_local_data *ctx,
			bool locked_by_caller),
		int (*recv_channel)(struct lttng_consumer_channel *channel),
		int (*recv_stream)(struct lttng_consumer_stream *stream),
		int (*update_stream)(uint64_t sessiond_key, uint32_t state));
void lttng_consumer_destroy(struct lttng_consumer_local_data *ctx);
ssize_t lttng_consumer_on_read_subbuffer_mmap(
		struct lttng_consumer_stream *stream,
		const struct lttng_buffer_view *buffer,
		unsigned long padding);
ssize_t lttng_consumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding);
int lttng_consumer_sample_snapshot_positions(struct lttng_consumer_stream *stream);
int lttng_consumer_take_snapshot(struct lttng_consumer_stream *stream);
int lttng_consumer_get_produced_snapshot(struct lttng_consumer_stream *stream,
		unsigned long *pos);
int lttng_consumer_get_consumed_snapshot(struct lttng_consumer_stream *stream,
		unsigned long *pos);
int lttng_ustconsumer_get_wakeup_fd(struct lttng_consumer_stream *stream);
int lttng_ustconsumer_close_wakeup_fd(struct lttng_consumer_stream *stream);
void *consumer_thread_metadata_poll(void *data);
void *consumer_thread_data_poll(void *data);
void *consumer_thread_sessiond_poll(void *data);
void *consumer_thread_channel_poll(void *data);
int lttng_consumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll);

ssize_t lttng_consumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx,
		bool locked_by_caller);
int lttng_consumer_on_recv_stream(struct lttng_consumer_stream *stream);
void consumer_add_relayd_socket(uint64_t net_seq_idx,
		int sock_type,
		struct lttng_consumer_local_data *ctx,
		int sock,
		struct pollfd *consumer_sockpoll,
		uint64_t sessiond_id,
		uint64_t relayd_session_id,
		uint32_t relayd_version_major,
		uint32_t relayd_version_minor,
		enum lttcomm_sock_proto relayd_socket_protocol);
void consumer_flag_relayd_for_destroy(
		struct consumer_relayd_sock_pair *relayd);
int consumer_data_pending(uint64_t id);
int consumer_send_status_msg(int sock, int ret_code);
int consumer_send_status_channel(int sock,
		struct lttng_consumer_channel *channel);
void notify_thread_del_channel(struct lttng_consumer_local_data *ctx,
		uint64_t key);
void consumer_destroy_relayd(struct consumer_relayd_sock_pair *relayd);
unsigned long consumer_get_consume_start_pos(unsigned long consumed_pos,
		unsigned long produced_pos, uint64_t nb_packets_per_stream,
		uint64_t max_sb_size);
void consumer_add_data_stream(struct lttng_consumer_stream *stream);
void consumer_del_stream_for_data(struct lttng_consumer_stream *stream);
void consumer_add_metadata_stream(struct lttng_consumer_stream *stream);
void consumer_del_stream_for_metadata(struct lttng_consumer_stream *stream);
int consumer_create_index_file(struct lttng_consumer_stream *stream);
int lttng_consumer_rotate_channel(struct lttng_consumer_channel *channel,
		uint64_t key, uint64_t relayd_id, uint32_t metadata,
		struct lttng_consumer_local_data *ctx);
int lttng_consumer_stream_is_rotate_ready(struct lttng_consumer_stream *stream);
int lttng_consumer_rotate_stream(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream);
int lttng_consumer_rotate_ready_streams(struct lttng_consumer_channel *channel,
		uint64_t key, struct lttng_consumer_local_data *ctx);
void lttng_consumer_reset_stream_rotate_state(struct lttng_consumer_stream *stream);
enum lttcomm_return_code lttng_consumer_create_trace_chunk(
		const uint64_t *relayd_id, uint64_t session_id,
		uint64_t chunk_id,
		time_t chunk_creation_timestamp,
		const char *chunk_override_name,
		const struct lttng_credentials *credentials,
		struct lttng_directory_handle *chunk_directory_handle);
enum lttcomm_return_code lttng_consumer_close_trace_chunk(
		const uint64_t *relayd_id, uint64_t session_id,
		uint64_t chunk_id, time_t chunk_close_timestamp,
		const enum lttng_trace_chunk_command_type *close_command,
		char *path);
enum lttcomm_return_code lttng_consumer_trace_chunk_exists(
		const uint64_t *relayd_id, uint64_t session_id,
		uint64_t chunk_id);
void lttng_consumer_cleanup_relayd(struct consumer_relayd_sock_pair *relayd);
enum lttcomm_return_code lttng_consumer_init_command(
		struct lttng_consumer_local_data *ctx,
		const lttng_uuid sessiond_uuid);
int lttng_consumer_clear_channel(struct lttng_consumer_channel *channel);
enum lttcomm_return_code lttng_consumer_open_channel_packets(
		struct lttng_consumer_channel *channel);
int consumer_metadata_wakeup_pipe(const struct lttng_consumer_channel *channel);
void lttng_consumer_sigbus_handle(void *addr);

#endif /* LIB_CONSUMER_H */
