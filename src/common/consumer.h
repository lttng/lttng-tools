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

/* Commands for consumer */
enum lttng_consumer_command {
	LTTNG_CONSUMER_ADD_CHANNEL,
	LTTNG_CONSUMER_ADD_STREAM,
	/* pause, delete, active depending on fd state */
	LTTNG_CONSUMER_UPDATE_STREAM,
	/* inform the consumer to quit when all fd has hang up */
	LTTNG_CONSUMER_STOP,
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
	/* Channel trace file path name. */
	char pathname[PATH_MAX];
	/* Channel name. */
	char name[LTTNG_SYMBOL_NAME_LEN];
	/* UID and GID of the channel. */
	uid_t uid;
	gid_t gid;
	/* Relayd id of the channel. -1 if it does not apply. */
	int64_t relayd_id;
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
	/* For metadata periodical flush */
	int switch_timer_enabled;
	timer_t switch_timer;
	/* On-disk circular buffer */
	uint64_t tracefile_size;
	uint64_t tracefile_count;
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
	enum lttng_consumer_stream_state state;
	int shm_fd_is_copy;
	int data_read;
	int hangup_flush_done;
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
	/* Identify if the stream is the metadata */
	unsigned int metadata_flag;
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
};

/*
 * Internal representation of a relayd socket pair.
 */
struct consumer_relayd_sock_pair {
	/* Network sequence number. */
	int64_t net_seq_idx;
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
	int (*on_update_stream)(int sessiond_key, uint32_t state);
	enum lttng_consumer_type type;
	/* socket to communicate errors with sessiond */
	int consumer_error_socket;
	/* socket to ask metadata to sessiond */
	int consumer_metadata_socket;
	/* socket to exchange commands with sessiond */
	char *consumer_command_sock_path;
	/* communication with splice */
	int consumer_thread_pipe[2];
	int consumer_channel_pipe[2];
	int consumer_splice_metadata_pipe[2];
	/* Data stream poll thread pipe. To transfer data stream to the thread */
	int consumer_data_pipe[2];
	/* to let the signal handler wake up the fd receiver thread */
	int consumer_should_quit[2];
	/* Metadata poll thread pipe. Transfer metadata stream to it */
	int consumer_metadata_pipe[2];
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
 * Init consumer data structures.
 */
void lttng_consumer_init(void);

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
 * Flush pending writes to trace output disk file.
 */
void lttng_consumer_sync_trace_file(struct lttng_consumer_stream *stream,
		off_t orig_offset);

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
		int relayd_id,
		uint64_t session_id,
		int cpu,
		int *alloc_ret,
		enum consumer_channel_type type);
struct lttng_consumer_channel *consumer_allocate_channel(uint64_t key,
		uint64_t session_id,
		const char *pathname,
		const char *name,
		uid_t uid,
		gid_t gid,
		int relayd_id,
		enum lttng_event_output output,
		uint64_t tracefile_size,
		uint64_t tracefile_count);
void consumer_del_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht);
void consumer_del_metadata_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht);
int consumer_add_channel(struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx);
void consumer_del_channel(struct lttng_consumer_channel *channel);

/* lttng-relayd consumer command */
struct consumer_relayd_sock_pair *consumer_allocate_relayd_sock_pair(
		int net_seq_idx);
struct consumer_relayd_sock_pair *consumer_find_relayd(uint64_t key);
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
		int (*update_stream)(int sessiond_key, uint32_t state));
void lttng_consumer_destroy(struct lttng_consumer_local_data *ctx);
ssize_t lttng_consumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding);
ssize_t lttng_consumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding);
int lttng_consumer_take_snapshot(struct lttng_consumer_stream *stream);
int lttng_consumer_get_produced_snapshot(struct lttng_consumer_stream *stream,
		unsigned long *pos);
void *consumer_thread_metadata_poll(void *data);
void *consumer_thread_data_poll(void *data);
void *consumer_thread_sessiond_poll(void *data);
void *consumer_thread_channel_poll(void *data);
int lttng_consumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll);

ssize_t lttng_consumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx);
int lttng_consumer_on_recv_stream(struct lttng_consumer_stream *stream);
int consumer_add_relayd_socket(int net_seq_idx, int sock_type,
		struct lttng_consumer_local_data *ctx, int sock,
		struct pollfd *consumer_sockpoll, struct lttcomm_relayd_sock *relayd_sock,
		unsigned int sessiond_id);
void consumer_flag_relayd_for_destroy(
		struct consumer_relayd_sock_pair *relayd);
int consumer_data_pending(uint64_t id);
int consumer_send_status_msg(int sock, int ret_code);
int consumer_send_status_channel(int sock,
		struct lttng_consumer_channel *channel);

#endif /* LIB_CONSUMER_H */
