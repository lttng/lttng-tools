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

#include <lttng/lttng.h>

#include <common/hashtable/hashtable.h>
#include <common/compat/fcntl.h>
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

struct lttng_consumer_channel {
	struct lttng_ht_node_ulong node;
	int key;
	uint64_t max_sb_size; /* the subbuffer size for this channel */
	int refcount; /* Number of streams referencing this channel */
	/*
	 * The number of streams to receive initially. Used to guarantee that we do
	 * not destroy a channel before receiving all its associated streams.
	 */
	unsigned int nb_init_streams;

	/* For UST */
	int shm_fd;
	int wait_fd;
	void *mmap_base;
	size_t mmap_len;
	struct lttng_ust_shm_handle *handle;
	int wait_fd_is_copy;
	int cpucount;
};

/* Forward declaration for UST. */
struct lttng_ust_lib_ring_buffer;

/*
 * Internal representation of the streams, sessiond_key is used to identify
 * uniquely a stream.
 */
struct lttng_consumer_stream {
	/* HT node used by the data_ht and metadata_ht */
	struct lttng_ht_node_ulong node;
	/* HT node used in consumer_data.stream_list_ht */
	struct lttng_ht_node_ulong node_session_id;
	struct lttng_consumer_channel *chan;	/* associated channel */
	/*
	 * key is the key used by the session daemon to refer to the
	 * object in the consumer daemon.
	 */
	int key;
	int shm_fd;
	int wait_fd;
	int out_fd; /* output file to write the data */
	off_t out_fd_offset; /* write position in the output file descriptor */
	char path_name[PATH_MAX]; /* tracefile name */
	enum lttng_consumer_stream_state state;
	size_t shm_len;
	void *mmap_base;
	size_t mmap_len;
	enum lttng_event_output output; /* splice or mmap */
	int shm_fd_is_copy;
	int wait_fd_is_copy;
	/* For UST */
	struct lttng_ust_lib_ring_buffer *buf;
	int cpu;
	int data_read;
	int hangup_flush_done;
	/* UID/GID of the user owning the session to which stream belongs */
	uid_t uid;
	gid_t gid;
	/* Network sequence number. Indicating on which relayd socket it goes. */
	int net_seq_idx;
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
};

/*
 * Internal representation of a relayd socket pair.
 */
struct consumer_relayd_sock_pair {
	/* Network sequence number. */
	int net_seq_idx;
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
	struct lttcomm_sock control_sock;

	/*
	 * We don't need a mutex at this point since we only splice or write single
	 * large chunk of data with a header appended at the begining. Moreover,
	 * this socket is for now only used in a single thread.
	 */
	struct lttcomm_sock data_sock;
	struct lttng_ht_node_ulong node;

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
	/* socket to communicate errors with sessiond */
	int consumer_error_socket;
	/* socket to exchange commands with sessiond */
	char *consumer_command_sock_path;
	/* communication with splice */
	int consumer_thread_pipe[2];
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
};

/*
 * Init consumer data structures.
 */
extern void lttng_consumer_init(void);

/*
 * Set the error socket for communication with a session daemon.
 */
extern void lttng_consumer_set_error_sock(
		struct lttng_consumer_local_data *ctx, int sock);

/*
 * Set the command socket path for communication with a session daemon.
 */
extern void lttng_consumer_set_command_sock_path(
		struct lttng_consumer_local_data *ctx, char *sock);

/*
 * Send return code to session daemon.
 *
 * Returns the return code of sendmsg : the number of bytes transmitted or -1
 * on error.
 */
extern int lttng_consumer_send_error(
		struct lttng_consumer_local_data *ctx, int cmd);

/*
 * Called from signal handler to ensure a clean exit.
 */
extern void lttng_consumer_should_exit(
		struct lttng_consumer_local_data *ctx);

/*
 * Cleanup the daemon's socket on exit.
 */
extern void lttng_consumer_cleanup(void);

/*
 * Flush pending writes to trace output disk file.
 */
extern void lttng_consumer_sync_trace_file(
		struct lttng_consumer_stream *stream, off_t orig_offset);

/*
 * Poll on the should_quit pipe and the command socket return -1 on error and
 * should exit, 0 if data is available on the command socket
 */
extern int lttng_consumer_poll_socket(struct pollfd *kconsumer_sockpoll);

extern struct lttng_consumer_stream *consumer_allocate_stream(
		int channel_key, int stream_key,
		int shm_fd, int wait_fd,
		enum lttng_consumer_stream_state state,
		uint64_t mmap_len,
		enum lttng_event_output output,
		const char *path_name,
		uid_t uid,
		gid_t gid,
		int net_index,
		int metadata_flag,
		uint64_t session_id,
		int *alloc_ret);
extern void consumer_del_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht);
extern void consumer_del_metadata_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht);
extern void consumer_del_channel(struct lttng_consumer_channel *channel);
extern struct lttng_consumer_channel *consumer_allocate_channel(
		int channel_key,
		int shm_fd, int wait_fd,
		uint64_t mmap_len,
		uint64_t max_sb_size,
		unsigned int nb_init_streams);
int consumer_add_channel(struct lttng_consumer_channel *channel);

/* lttng-relayd consumer command */
struct consumer_relayd_sock_pair *consumer_allocate_relayd_sock_pair(
		int net_seq_idx);
struct consumer_relayd_sock_pair *consumer_find_relayd(int key);
int consumer_handle_stream_before_relayd(struct lttng_consumer_stream *stream,
		size_t data_size);
void consumer_steal_stream_key(int key, struct lttng_ht *ht);

extern struct lttng_consumer_local_data *lttng_consumer_create(
		enum lttng_consumer_type type,
		ssize_t (*buffer_ready)(struct lttng_consumer_stream *stream,
			struct lttng_consumer_local_data *ctx),
		int (*recv_channel)(struct lttng_consumer_channel *channel),
		int (*recv_stream)(struct lttng_consumer_stream *stream),
		int (*update_stream)(int sessiond_key, uint32_t state));
extern void lttng_consumer_destroy(struct lttng_consumer_local_data *ctx);
extern ssize_t lttng_consumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding);
extern ssize_t lttng_consumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding);
extern int lttng_consumer_take_snapshot(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream);
extern int lttng_consumer_get_produced_snapshot(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream,
		unsigned long *pos);
extern void *consumer_thread_metadata_poll(void *data);
extern void *consumer_thread_data_poll(void *data);
extern void *consumer_thread_sessiond_poll(void *data);
extern int lttng_consumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll);

ssize_t lttng_consumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx);
int lttng_consumer_on_recv_stream(struct lttng_consumer_stream *stream);
int consumer_add_relayd_socket(int net_seq_idx, int sock_type,
		struct lttng_consumer_local_data *ctx, int sock,
		struct pollfd *consumer_sockpoll, struct lttcomm_sock *relayd_sock,
		unsigned int sessiond_id);
void consumer_flag_relayd_for_destroy(
		struct consumer_relayd_sock_pair *relayd);
int consumer_data_pending(uint64_t id);
int consumer_send_status_msg(int sock, int ret_code);

#endif /* LIB_CONSUMER_H */
