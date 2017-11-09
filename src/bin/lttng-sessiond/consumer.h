/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _CONSUMER_H
#define _CONSUMER_H

#include <common/consumer/consumer.h>
#include <common/hashtable/hashtable.h>
#include <lttng/lttng.h>
#include <urcu/ref.h>

#include "snapshot.h"

struct snapshot;
struct snapshot_output;

enum consumer_dst_type {
	CONSUMER_DST_LOCAL,
	CONSUMER_DST_NET,
};

struct consumer_socket {
	/*
	 * File descriptor. This is just a reference to the consumer data meaning
	 * that every access must be locked and checked for a possible invalid
	 * value.
	 */
	int *fd_ptr;

	/*
	 * To use this socket (send/recv), this lock MUST be acquired.
	 */
	pthread_mutex_t *lock;

	/*
	 * Indicates if the socket was registered by a third part
	 * (REGISTER_CONSUMER) or is the spawn consumer of the session daemon.
	 * During the destroy phase of a consumer output, we close the socket if
	 * this flag is set to 1 since we don't need the fd anymore.
	 */
	unsigned int registered;

	/* Flag if network sockets were sent to the consumer. */
	unsigned int control_sock_sent;
	unsigned int data_sock_sent;

	struct lttng_ht_node_ulong node;

	enum lttng_consumer_type type;
};

struct consumer_data {
	enum lttng_consumer_type type;

	pthread_t thread;	/* Worker thread interacting with the consumer */

	/* Conditions used by the consumer thread to indicate readiness. */
	pthread_cond_t cond;
	pthread_condattr_t condattr;
	pthread_mutex_t cond_mutex;

	/*
	 * This is a flag condition indicating that the consumer thread is ready
	 * and connected to the lttng-consumerd daemon. This flag MUST only be
	 * updated by locking the condition mutex above or before spawning a
	 * consumer thread.
	 *
	 * A value of 0 means that the thread is NOT ready. A value of 1 means that
	 * the thread consumer did connect successfully to the lttng-consumerd
	 * daemon. A negative value indicates that there is been an error and the
	 * thread has likely quit.
	 */
	int consumer_thread_is_ready;

	/* Mutex to control consumerd pid assignation */
	pthread_mutex_t pid_mutex;
	pid_t pid;

	int err_sock;
	/* These two sockets uses the cmd_unix_sock_path. */
	int cmd_sock;
	/*
	 * Write-end of the channel monitoring pipe to be passed to the
	 * consumer.
	 */
	int channel_monitor_pipe;
	/*
	 * The metadata socket object is handled differently and only created
	 * locally in this object thus it's the only reference available in the
	 * session daemon. For that reason, a variable for the fd is required and
	 * the metadata socket fd points to it.
	 */
	int metadata_fd;
	struct consumer_socket metadata_sock;

	/* consumer error and command Unix socket path */
	const char *err_unix_sock_path;
	const char *cmd_unix_sock_path;

	/*
	 * This lock has two purposes. It protects any change to the consumer
	 * socket and make sure only one thread uses this object for read/write
	 * operations.
	 */
	pthread_mutex_t lock;
};

/*
 * Network URIs
 */
struct consumer_net {
	/*
	 * Indicate if URI type is set. Those flags should only be set when the
	 * created URI is done AND valid.
	 */
	int control_isset;
	int data_isset;

	/*
	 * The following two URIs MUST have the same destination address for
	 * network streaming to work. Network hop are not yet supported.
	 */

	/* Control path for network streaming. */
	struct lttng_uri control;

	/* Data path for network streaming. */
	struct lttng_uri data;
};

/*
 * Consumer output object describing where and how to send data.
 */
struct consumer_output {
	struct urcu_ref ref;	/* Refcount */

	/* If the consumer is enabled meaning that should be used */
	unsigned int enabled;
	enum consumer_dst_type type;

	/*
	 * The net_seq_index is the index of the network stream on the consumer
	 * side. It tells the consumer which streams goes to which relayd with this
	 * index. The relayd sockets are index with it on the consumer side.
	 */
	uint64_t net_seq_index;
	/* Store the relay protocol in use if the session is remote. */
	uint32_t relay_major_version;
	uint32_t relay_minor_version;

	/*
	 * Subdirectory path name used for both local and network consumer.
	 */
	char subdir[PATH_MAX];

	/*
	 * Hashtable of consumer_socket index by the file descriptor value. For
	 * multiarch consumer support, we can have more than one consumer (ex: 32
	 * and 64 bit).
	 */
	struct lttng_ht *socks;

	/* Tell if this output is used for snapshot. */
	unsigned int snapshot:1;

	union {
		char trace_path[PATH_MAX];
		struct consumer_net net;
	} dst;
};

struct consumer_socket *consumer_find_socket(int key,
		struct consumer_output *consumer);
struct consumer_socket *consumer_find_socket_by_bitness(int bits,
		struct consumer_output *consumer);
struct consumer_socket *consumer_allocate_socket(int *fd);
void consumer_add_socket(struct consumer_socket *sock,
		struct consumer_output *consumer);
void consumer_del_socket(struct consumer_socket *sock,
		struct consumer_output *consumer);
void consumer_destroy_socket(struct consumer_socket *sock);
int consumer_copy_sockets(struct consumer_output *dst,
		struct consumer_output *src);
void consumer_destroy_output_sockets(struct consumer_output *obj);
int consumer_socket_send(struct consumer_socket *socket, void *msg,
		size_t len);
int consumer_socket_recv(struct consumer_socket *socket, void *msg,
		size_t len);

struct consumer_output *consumer_create_output(enum consumer_dst_type type);
struct consumer_output *consumer_copy_output(struct consumer_output *obj);
void consumer_output_get(struct consumer_output *obj);
void consumer_output_put(struct consumer_output *obj);
int consumer_set_network_uri(struct consumer_output *obj,
		struct lttng_uri *uri);
int consumer_send_fds(struct consumer_socket *sock, int *fds, size_t nb_fd);
int consumer_send_msg(struct consumer_socket *sock,
		struct lttcomm_consumer_msg *msg);
int consumer_send_stream(struct consumer_socket *sock,
		struct consumer_output *dst, struct lttcomm_consumer_msg *msg,
		int *fds, size_t nb_fd);
int consumer_send_channel(struct consumer_socket *sock,
		struct lttcomm_consumer_msg *msg);
int consumer_send_relayd_socket(struct consumer_socket *consumer_sock,
		struct lttcomm_relayd_sock *rsock, struct consumer_output *consumer,
		enum lttng_stream_type type, uint64_t session_id,
		char *session_name, char *hostname, int session_live_timer);
int consumer_send_channel_monitor_pipe(struct consumer_socket *consumer_sock,
		int pipe);
int consumer_send_destroy_relayd(struct consumer_socket *sock,
		struct consumer_output *consumer);
int consumer_recv_status_reply(struct consumer_socket *sock);
int consumer_recv_status_channel(struct consumer_socket *sock,
		uint64_t *key, unsigned int *stream_count);
void consumer_output_send_destroy_relayd(struct consumer_output *consumer);
int consumer_create_socket(struct consumer_data *data,
		struct consumer_output *output);
int consumer_set_subdir(struct consumer_output *consumer,
		const char *session_name);

void consumer_init_ask_channel_comm_msg(struct lttcomm_consumer_msg *msg,
		uint64_t subbuf_size,
		uint64_t num_subbuf,
		int overwrite,
		unsigned int switch_timer_interval,
		unsigned int read_timer_interval,
		unsigned int live_timer_interval,
		unsigned int monitor_timer_interval,
		int output,
		int type,
		uint64_t session_id,
		const char *pathname,
		const char *name,
		uid_t uid,
		gid_t gid,
		uint64_t relayd_id,
		uint64_t key,
		unsigned char *uuid,
		uint32_t chan_id,
		uint64_t tracefile_size,
		uint64_t tracefile_count,
		uint64_t session_id_per_pid,
		unsigned int monitor,
		uint32_t ust_app_uid,
		int64_t blocking_timeout,
		const char *root_shm_path,
		const char *shm_path);
void consumer_init_stream_comm_msg(struct lttcomm_consumer_msg *msg,
		enum lttng_consumer_command cmd,
		uint64_t channel_key,
		uint64_t stream_key,
		int cpu);
void consumer_init_streams_sent_comm_msg(struct lttcomm_consumer_msg *msg,
		enum lttng_consumer_command cmd,
		uint64_t channel_key, uint64_t net_seq_idx);
void consumer_init_channel_comm_msg(struct lttcomm_consumer_msg *msg,
		enum lttng_consumer_command cmd,
		uint64_t channel_key,
		uint64_t session_id,
		const char *pathname,
		uid_t uid,
		gid_t gid,
		uint64_t relayd_id,
		const char *name,
		unsigned int nb_init_streams,
		enum lttng_event_output output,
		int type,
		uint64_t tracefile_size,
		uint64_t tracefile_count,
		unsigned int monitor,
		unsigned int live_timer_interval,
		unsigned int monitor_timer_interval);
int consumer_is_data_pending(uint64_t session_id,
		struct consumer_output *consumer);
int consumer_close_metadata(struct consumer_socket *socket,
		uint64_t metadata_key);
int consumer_setup_metadata(struct consumer_socket *socket,
		uint64_t metadata_key);
int consumer_push_metadata(struct consumer_socket *socket,
		uint64_t metadata_key, char *metadata_str, size_t len,
		size_t target_offset, uint64_t version);
int consumer_flush_channel(struct consumer_socket *socket, uint64_t key);
int consumer_clear_quiescent_channel(struct consumer_socket *socket, uint64_t key);
int consumer_get_discarded_events(uint64_t session_id, uint64_t channel_key,
		struct consumer_output *consumer, uint64_t *discarded);
int consumer_get_lost_packets(uint64_t session_id, uint64_t channel_key,
		struct consumer_output *consumer, uint64_t *lost);

/* Snapshot command. */
int consumer_snapshot_channel(struct consumer_socket *socket, uint64_t key,
		struct snapshot_output *output, int metadata, uid_t uid, gid_t gid,
		const char *session_path, int wait, uint64_t nb_packets_per_stream);

#endif /* _CONSUMER_H */
