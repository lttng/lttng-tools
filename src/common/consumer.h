/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _LTTNG_CONSUMER_H
#define _LTTNG_CONSUMER_H

#include <limits.h>
#include <poll.h>
#include <unistd.h>

#include <lttng/lttng.h>

#include <common/hashtable/hashtable.h>
#include <common/compat/fcntl.h>

/*
 * When the receiving thread dies, we need to have a way to make the polling
 * thread exit eventually. If all FDs hang up (normal case when the
 * lttng-sessiond stops), we can exit cleanly, but if there is a problem and
 * for whatever reason some FDs remain open, the consumer should still exit
 * eventually.
 *
 * If the timeout is reached, it means that during this period no events
 * occurred on the FDs so we need to force an exit. This case should not happen
 * but it is a safety to ensure we won't block the consumer indefinitely.
 *
 * The value of 2 seconds is an arbitrary choice.
 */
#define LTTNG_CONSUMER_POLL_TIMEOUT 2000

/* Commands for consumer */
enum lttng_consumer_command {
	LTTNG_CONSUMER_ADD_CHANNEL,
	LTTNG_CONSUMER_ADD_STREAM,
	/* pause, delete, active depending on fd state */
	LTTNG_CONSUMER_UPDATE_STREAM,
	/* inform the consumer to quit when all fd has hang up */
	LTTNG_CONSUMER_STOP,
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

struct lttng_consumer_channel {
	struct lttng_ht_node_ulong node;
	int key;
	uint64_t max_sb_size; /* the subbuffer size for this channel */
	int refcount; /* Number of streams referencing this channel */
	/* For UST */
	int shm_fd;
	int wait_fd;
	void *mmap_base;
	size_t mmap_len;
	struct lttng_ust_shm_handle *handle;
	int nr_streams;
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
	struct lttng_ht_node_ulong node;
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
	int hangup_flush_done;
	/* UID/GID of the user owning the session to which stream belongs */
	uid_t uid;
	gid_t gid;
};

/*
 * UST consumer local data to the program. One or more instance per
 * process.
 */
struct lttng_consumer_local_data {
	/* function to call when data is available on a buffer */
	int (*on_buffer_ready)(struct lttng_consumer_stream *stream,
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
	/* pipe to wake the poll thread when necessary */
	int consumer_poll_pipe[2];
	/* to let the signal handler wake up the fd receiver thread */
	int consumer_should_quit[2];
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
	 * XXX: We need to see if this lock is still needed with the lockless RCU
	 * hash tables.
	 */
	pthread_mutex_t lock;

	/*
	 * Number of streams in the hash table. Protected by consumer_data.lock.
	 */
	int stream_count;
	/*
	 * Hash tables of streams and channels. Protected by consumer_data.lock.
	 */
	struct lttng_ht *stream_ht;
	struct lttng_ht *channel_ht;
	/*
	 * Flag specifying if the local array of FDs needs update in the
	 * poll function. Protected by consumer_data.lock.
	 */
	unsigned int need_update;
	enum lttng_consumer_type type;
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

extern int consumer_update_poll_array(
		struct lttng_consumer_local_data *ctx, struct pollfd **pollfd,
		struct lttng_consumer_stream **local_consumer_streams);

extern struct lttng_consumer_stream *consumer_allocate_stream(
		int channel_key, int stream_key,
		int shm_fd, int wait_fd,
		enum lttng_consumer_stream_state state,
		uint64_t mmap_len,
		enum lttng_event_output output,
		const char *path_name,
		uid_t uid,
		gid_t gid);
extern int consumer_add_stream(struct lttng_consumer_stream *stream);
extern void consumer_del_stream(struct lttng_consumer_stream *stream);
extern void consumer_change_stream_state(int stream_key,
		enum lttng_consumer_stream_state state);
extern void consumer_del_channel(struct lttng_consumer_channel *channel);
extern struct lttng_consumer_channel *consumer_allocate_channel(
		int channel_key,
		int shm_fd, int wait_fd,
		uint64_t mmap_len,
		uint64_t max_sb_size);
int consumer_add_channel(struct lttng_consumer_channel *channel);

extern struct lttng_consumer_local_data *lttng_consumer_create(
		enum lttng_consumer_type type,
		int (*buffer_ready)(struct lttng_consumer_stream *stream,
			struct lttng_consumer_local_data *ctx),
		int (*recv_channel)(struct lttng_consumer_channel *channel),
		int (*recv_stream)(struct lttng_consumer_stream *stream),
		int (*update_stream)(int sessiond_key, uint32_t state));
extern void lttng_consumer_destroy(struct lttng_consumer_local_data *ctx);
extern int lttng_consumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len);
extern int lttng_consumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len);
extern int lttng_consumer_take_snapshot(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream);
extern int lttng_consumer_get_produced_snapshot(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream,
		unsigned long *pos);
extern void *lttng_consumer_thread_poll_fds(void *data);
extern void *lttng_consumer_thread_receive_fds(void *data);
extern int lttng_consumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll);

int lttng_consumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx);
int lttng_consumer_on_recv_stream(struct lttng_consumer_stream *stream);

#endif /* _LTTNG_CONSUMER_H */
