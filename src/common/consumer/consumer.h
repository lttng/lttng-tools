/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LIB_CONSUMER_H
#define LIB_CONSUMER_H

#include <limits.h>
#include <poll.h>
#include <unistd.h>
#include <urcu/list.h>

#include <lttng/lttng.h>

#include <common/hashtable/hashtable.h>
#include <common/compat/fcntl.h>
#include <common/compat/uuid.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/pipe.h>
#include <common/index/ctf-index.h>

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
};

/* State of each fd in consumer */
enum lttng_consumer_stream_state {
	LTTNG_CONSUMER_ACTIVE_STREAM,
	LTTNG_CONSUMER_PAUSE_STREAM,
	LTTNG_CONSUMER_DELETE_STREAM,
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

extern struct lttng_consumer_global_data consumer_data;

struct stream_list {
	struct cds_list_head head;
	unsigned int count;
};

/* Stub. */
struct consumer_metadata_cache;

struct lttng_consumer_channel {
	/* HT node used for consumer_data.channel_ht */
	struct lttng_ht_node_u64 node;
	/* Indexed key. Incremented value in the consumer. */
	uint64_t key;
	/* Number of streams referencing this channel */
	int refcount;
	/* Tracing session id on the session daemon side. */
	uint64_t session_id;
	/*
	 * Session id when requesting metadata to the session daemon for
	 * a session with per-PID buffers.
	 */
	uint64_t session_id_per_pid;
	/* Channel trace file path name. */
	char pathname[PATH_MAX];
	/* Channel name. */
	char name[LTTNG_SYMBOL_NAME_LEN];
	/* UID and GID of the session owning this channel. */
	uid_t uid;
	gid_t gid;
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
	struct ustctl_consumer_channel *uchan;
	unsigned char uuid[UUID_STR_LEN];
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

	/* For UST metadata periodical flush */
	int switch_timer_enabled;
	timer_t switch_timer;
	int switch_timer_error;

	/* For the live mode */
	int live_timer_enabled;
	timer_t live_timer;
	int live_timer_error;

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
	/* Total number of discarded events for that channel. */
	uint64_t discarded_events;
	/* Total number of missed packets due to overwriting (overwrite). */
	uint64_t lost_packets;

	bool streams_sent_to_relayd;
};

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
	/* Pointer to associated channel. */
	struct lttng_consumer_channel *chan;

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
	enum lttng_consumer_stream_state state;
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
	/* Maximum subbuffer size. */
	unsigned long max_sb_size;

	/*
	 * Still used by the kernel for MMAP output. For UST, the ustctl getter is
	 * used for the mmap base and offset.
	 */
	void *mmap_base;
	unsigned long mmap_len;

	/* For UST */

	int wait_fd;
	/* UID/GID of the user owning the session to which stream belongs */
	uid_t uid;
	gid_t gid;
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
	struct ustctl_consumer_stream *ustream;
	struct cds_list_head send_node;
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

	/* Indicate if the stream still has some data to be read. */
	unsigned int has_data:1;
	/*
	 * Inform the consumer or relay to reset the metadata
	 * file before writing in it (regeneration).
	 */
	unsigned int reset_metadata_flag:1;
};

/*
 * Internal representation of a relayd socket pair.
 */
struct consumer_relayd_sock_pair {
	/* Network sequence number. */
	uint64_t net_seq_idx;
	/* Number of stream associated with this relayd */
	unsigned int refcount;

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
			struct lttng_consumer_local_data *ctx);
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
int lttng_consumer_send_error(struct lttng_consumer_local_data *ctx, int cmd);

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

struct lttng_consumer_stream *consumer_allocate_stream(uint64_t channel_key,
		uint64_t stream_key,
		enum lttng_consumer_stream_state state,
		const char *channel_name,
		uid_t uid,
		gid_t gid,
		uint64_t relayd_id,
		uint64_t session_id,
		int cpu,
		int *alloc_ret,
		enum consumer_channel_type type,
		unsigned int monitor);
struct lttng_consumer_channel *consumer_allocate_channel(uint64_t key,
		uint64_t session_id,
		const char *pathname,
		const char *name,
		uid_t uid,
		gid_t gid,
		uint64_t relayd_id,
		enum lttng_event_output output,
		uint64_t tracefile_size,
		uint64_t tracefile_count,
		uint64_t session_id_per_pid,
		unsigned int monitor,
		unsigned int live_timer_interval,
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
			struct lttng_consumer_local_data *ctx),
		int (*recv_channel)(struct lttng_consumer_channel *channel),
		int (*recv_stream)(struct lttng_consumer_stream *stream),
		int (*update_stream)(uint64_t sessiond_key, uint32_t state));
void lttng_consumer_destroy(struct lttng_consumer_local_data *ctx);
ssize_t lttng_consumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding,
		struct ctf_packet_index *index);
ssize_t lttng_consumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding,
		struct ctf_packet_index *index);
int lttng_consumer_take_snapshot(struct lttng_consumer_stream *stream);
int lttng_consumer_get_produced_snapshot(struct lttng_consumer_stream *stream,
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
		struct lttng_consumer_local_data *ctx);
int lttng_consumer_on_recv_stream(struct lttng_consumer_stream *stream);
void consumer_add_relayd_socket(uint64_t net_seq_idx, int sock_type,
		struct lttng_consumer_local_data *ctx, int sock,
		struct pollfd *consumer_sockpoll, struct lttcomm_relayd_sock *relayd_sock,
		uint64_t sessiond_id, uint64_t relayd_session_id);
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

#endif /* LIB_CONSUMER_H */
