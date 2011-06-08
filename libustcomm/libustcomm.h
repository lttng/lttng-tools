/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 *               2010  Nils Carlson <nils.carlson@ericsson.com>
 *               2011  David Goulet <david.goulet@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _LTT_LIBUSTCOMM_H
#define _LTT_LIBUSTCOMM_H

#include <sys/types.h>
#include <sys/un.h>
#include <urcu/list.h>

#include "lttng-share.h"

#define UST_SOCK_DIR "/tmp/ust-app-socks"
#define USER_TMP_DIR "/tmp"
#define USER_SOCK_DIR_BASE "ust-socks-"
#define USER_SOCK_DIR USER_TMP_DIR "/" USER_SOCK_DIR_BASE

struct ustcomm_sock {
	struct cds_list_head list;
	int fd;
	int epoll_fd;
};

struct ustcomm_header {
	int command;
	long size;
	int result;
	int fd_included;
};

#define USTCOMM_BUFFER_SIZE ((1 << 12) - sizeof(struct ustcomm_header))

/*
 * Specify a sata size that leaves margin at the end of a buffer
 * in order to make sure that we never have more data than
 * will fit in the buffer AND that the last chars (due to a
 * pre-receive memset) will always be 0, terminating any string
 */
#define USTCOMM_DATA_SIZE (USTCOMM_BUFFER_SIZE - 20 * sizeof(void *))

enum ustcomm_tracectl_commands {
	ALLOC_TRACE,
	CONSUME_BUFFER,
	CREATE_TRACE,
	DESTROY_TRACE,
	DISABLE_MARKER,
	ENABLE_MARKER,
	EXIT,
	FORCE_SUBBUF_SWITCH,
	GET_BUF_SHMID_PIPE_FD,
	GET_PIDUNIQUE,
	GET_SOCK_PATH,
	GET_SUBBUFFER,
	GET_SUBBUF_NUM_SIZE,
	LIST_MARKERS,
	LIST_TRACE_EVENTS,
	LOAD_PROBE_LIB,
	NOTIFY_BUF_MAPPED,
	PRINT_MARKERS,
	PRINT_TRACE_EVENTS,
	PUT_SUBBUFFER,
	SETUP_TRACE,
	SET_SOCK_PATH,
	SET_SUBBUF_NUM,
	SET_SUBBUF_SIZE,
	START,
	START_TRACE,
	STOP_TRACE,
};

struct ustcomm_single_field {
	char *field;
	char data[USTCOMM_DATA_SIZE];
};

struct ustcomm_channel_info {
	char *trace;
	char *channel;
	unsigned int subbuf_size;
	unsigned int subbuf_num;
	char data[USTCOMM_DATA_SIZE];
};

struct ustcomm_buffer_info {
	char *trace;
	char *channel;
	int ch_cpu;
	pid_t pid;
	int buf_shmid;
	int buf_struct_shmid;
	long consumed_old;
	char data[USTCOMM_DATA_SIZE];
};

struct ustcomm_ust_marker_info {
	char *trace;
	char *channel;
	char *ust_marker;
	char data[USTCOMM_DATA_SIZE];
};

struct ustcomm_pidunique {
	s64 pidunique;
};

struct ustcomm_notify_buf_mapped {
	char data[USTCOMM_DATA_SIZE];
};

/* Create and delete sockets */
struct ustcomm_sock *ustcomm_init_sock(int fd, int epoll_fd, struct cds_list_head *list);
void ustcomm_del_sock(struct ustcomm_sock *sock, int keep_in_epoll);

/* Create and delete named sockets */
struct ustcomm_sock *ustcomm_init_named_socket(const char *name, int epoll_fd);
void ustcomm_del_named_sock(struct ustcomm_sock *sock, int keep_socket_file);

/* Send and receive functions for file descriptors */
int ustcomm_send_fd(int sock, const struct ustcomm_header *header,
		const char *data, int *fd);
int ustcomm_recv_fd(int sock, struct ustcomm_header *header,
		char *data, int *fd);

/* Normal send and receive functions */
int ustcomm_send(int sock, const struct ustcomm_header *header,
		const char *data);
int ustcomm_recv(int sock, struct ustcomm_header *header,
		char *data);

/* Receive and allocate data, not to be used inside libust */
int ustcomm_recv_alloc(int sock, struct ustcomm_header *header, char **data);

/* Request function, send and receive */
int ustcomm_req(int sock,
		const struct ustcomm_header *req_header,
		const char *req_data,
		struct ustcomm_header *res_header,
		char *res_data);

int ustcomm_request_consumer(pid_t pid, const char *channel);

/* Returns the current users socket directory, must be freed */
char *ustcomm_user_sock_dir(void);

/* Get the st_m_time from proc*/
time_t ustcomm_pid_st_mtime(pid_t pid);

/* Check that a socket is live */
int ustcomm_is_socket_live(char *sock_name, pid_t *read_pid);

int ustcomm_connect_app(pid_t pid, int *app_fd);
int ustcomm_connect_path(const char *path, int *connection_fd);

/* String serialising functions, printf straight into a buffer */
#define USTCOMM_POISON_PTR (void *)0x19831018

char *ustcomm_print_data(char *data_field, int field_size,
		int *offset, const char *format, ...);
char *ustcomm_restore_ptr(char *ptr, char *data_field, int data_field_size);

#define COMPUTE_MSG_SIZE(struct_ptr, offset)				\
	(size_t) (long)(struct_ptr)->data - (long)(struct_ptr) + (offset)

/* Packing and unpacking functions, making life easier */
int ustcomm_pack_single_field(struct ustcomm_header *header,
		struct ustcomm_single_field *sf, const char *trace);

int ustcomm_unpack_single_field(struct ustcomm_single_field *sf);

int ustcomm_pack_channel_info(struct ustcomm_header *header,
		struct ustcomm_channel_info *ch_inf,
		const char *trace, const char *channel);

int ustcomm_unpack_channel_info(struct ustcomm_channel_info *ch_inf);

int ustcomm_pack_buffer_info(struct ustcomm_header *header,
		struct ustcomm_buffer_info *buf_inf,
		const char *trace,
		const char *channel,
		int channel_cpu);

int ustcomm_unpack_buffer_info(struct ustcomm_buffer_info *buf_inf);

int ustcomm_pack_ust_marker_info(struct ustcomm_header *header,
		struct ustcomm_ust_marker_info *ust_marker_inf,
		const char *trace,
		const char *channel,
		const char *ust_marker);

int ustcomm_unpack_ust_marker_info(struct ustcomm_ust_marker_info *ust_marker_inf);

#endif /* _LTT_LIBUSTCOMM_H */
