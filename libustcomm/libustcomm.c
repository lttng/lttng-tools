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

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "libustcomm.h"
#include "lttngerr.h"

#define MAX_SOCK_PATH_BASE_LEN 100

/*
 *  get_sock_name
 *
 *  Set sock_name to the libust socket path using the pid
 *  and the base directory dir_name.
 */
static int get_sock_name(char *dir_name, pid_t pid, char *sock_name)
{
	struct dirent *dirent;
	char sock_path_base[MAX_SOCK_PATH_BASE_LEN];
	int len;
	DIR *dir;

	dir = opendir(dir_name);
	if (dir == NULL) {
		ERR("ustcomm sock name opendir %s", dir_name);
		goto out_err;
	}

	snprintf(sock_path_base, MAX_SOCK_PATH_BASE_LEN - 1, "%ld", (long) pid);
	len = strlen(sock_path_base);

	DBG("Socket directory %s", sock_path_base);

	while ((dirent = readdir(dir))) {
		if (!strcmp(dirent->d_name, ".") ||
				!strcmp(dirent->d_name, "..") ||
				!strcmp(dirent->d_name, "ust-consumer") ||
				dirent->d_type == DT_DIR ||
				strncmp(dirent->d_name, sock_path_base, len) != 0) {
			continue;
		}

		if (snprintf(sock_name, PATH_MAX - 1, "%s/%s", dir_name, dirent->d_name) < 0) {
			perror("path longer than PATH_MAX?");
			goto out_err;
		}

		break;
	}

	return 0;

out_err:
	closedir(dir);
	return -1;
}

/*
 *  create_sock_addr
 *
 *  Create a sockaddr structure for unic socket.
 */
static struct sockaddr_un *create_sock_addr(const char *name, size_t *sock_addr_size)
{
	struct sockaddr_un * addr;
	size_t alloc_size;

	alloc_size = (size_t) (((struct sockaddr_un *) 0)->sun_path) +
		strlen(name) + 1;

	addr = malloc(alloc_size);
	if (addr < 0) {
		ERR("allocating addr failed");
		return NULL;
	}

	addr->sun_family = AF_UNIX;
	strcpy(addr->sun_path, name);

	*sock_addr_size = alloc_size;

	return addr;
}

/*
 *  connect_app_non_root
 *
 *  Open a connection to a non root traceable app.
 *  On error, return -1 else 0
 */
static int connect_app_non_root(pid_t pid, int *app_fd)
{
	int result;
	int retval = 0;
	char *dir_name;
	char sock_name[PATH_MAX];

	dir_name = ustcomm_user_sock_dir();
	if (!dir_name) {
		return -ENOMEM;
	}

	if (get_sock_name(dir_name, pid, sock_name)) {
		retval = -ENOENT;
		goto free_dir_name;
	}

	result = ustcomm_connect_path(sock_name, app_fd);
	if (result < 0) {
		ERR("failed to connect to app");
		retval = -1;
		goto free_dir_name;
	}

free_dir_name:
	free(dir_name);

	return retval;
}

/*
 *  connect_app_root
 *
 *  Open a connection to a root traceable app.
 *  On error, return -1 else 0
 */
static int connect_app_root(pid_t pid, int *app_fd)
{
	DIR *tmp_dir;
	struct dirent *dirent;
	char dir_name[PATH_MAX], sock_name[PATH_MAX];
	int result = -1;

	tmp_dir = opendir(USER_TMP_DIR);
	if (!tmp_dir) {
		return -1;
	}

	while ((dirent = readdir(tmp_dir))) {
		if (!strncmp(dirent->d_name, USER_SOCK_DIR_BASE,
					strlen(USER_SOCK_DIR_BASE))) {

			if (snprintf(dir_name, PATH_MAX - 1, "%s/%s", USER_TMP_DIR,
						dirent->d_name) < 0) {
				continue;
			}

			if (get_sock_name(dir_name, pid, sock_name)) {
				continue;
			}

			result = ustcomm_connect_path(sock_name, app_fd);

			if (result == 0) {
				goto close_tmp_dir;
			}
		}
	}

close_tmp_dir:
	closedir(tmp_dir);

	return result;
}

/*
 *  time_and_pid_from_socket_name
 *
 *  Get time from socket name
 */
static int time_and_pid_from_socket_name(char *sock_name, unsigned long *time,
		pid_t *pid)
{
	char *saveptr, *pid_m_time_str;
	char *sock_basename = strdup(basename(sock_name));

	if (!sock_basename) {
		return -1;
	}

	/* This is the pid */
	pid_m_time_str = strtok_r(sock_basename, ".", &saveptr);
	if (!pid_m_time_str) {
		goto out_err;
	}

	errno = 0;
	*pid = (pid_t)strtoul(pid_m_time_str, NULL, 10);
	if (errno) {
		goto out_err;
	}

	/* This should be the time-stamp */
	pid_m_time_str = strtok_r(NULL, ".", &saveptr);
	if (!pid_m_time_str) {
		goto out_err;
	}

	errno = 0;
	*time = strtoul(pid_m_time_str, NULL, 10);
	if (errno) {
		goto out_err;
	}

	return 0;

out_err:
	free(sock_basename);
	return -1;
}

/*
 *  ustcomm_is_socket_live
 *
 *  Check if socket is available and "living".
 */
int ustcomm_is_socket_live(char *sock_name, pid_t *read_pid)
{
	time_t time_from_pid;
	unsigned long time_from_sock;
	pid_t pid;

	if (time_and_pid_from_socket_name(sock_name, &time_from_sock, &pid)) {
		return 0;
	}

	if (read_pid) {
		*read_pid = pid;
	}

	time_from_pid = ustcomm_pid_st_mtime(pid);
	if (!time_from_pid) {
		return 0;
	}

	if ((unsigned long) time_from_pid == time_from_sock) {
		return 1;
	}

	return 0;
}

/*
 *  ustcomm_init_sock
 *
 *  Init socket for communication between libust and libustcomm.
 */
struct ustcomm_sock *ustcomm_init_sock(int fd, int epoll_fd,
					struct cds_list_head *list)
{
	struct epoll_event ev;
	struct ustcomm_sock *sock;

	sock = malloc(sizeof(struct ustcomm_sock));
	if (!sock) {
		perror("malloc: couldn't allocate ustcomm_sock");
		return NULL;
	}

	ev.events = EPOLLIN;
	ev.data.ptr = sock;
	sock->fd = fd;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock->fd, &ev) == -1) {
		perror("epoll_ctl: failed to add socket\n");
		free(sock);
		return NULL;
	}

	sock->epoll_fd = epoll_fd;
	if (list) {
		cds_list_add(&sock->list, list);
	} else {
		CDS_INIT_LIST_HEAD(&sock->list);
	}

	return sock;
}

/*
 *  ustcomm_del_sock
 *
 *  Delete socket and remove it from the epoll set.
 */
void ustcomm_del_sock(struct ustcomm_sock *sock, int keep_in_epoll)
{
	cds_list_del(&sock->list);
	if (!keep_in_epoll) {
		if (epoll_ctl(sock->epoll_fd, EPOLL_CTL_DEL, sock->fd, NULL) == -1) {
			perror("epoll_ctl: failed to delete socket");
		}
	}
	close(sock->fd);
	free(sock);
}

/*
 *  ustcomm_init_named_socket
 *
 *  Init unix named socket
 */
struct ustcomm_sock *ustcomm_init_named_socket(const char *name, int epoll_fd)
{
	int result;
	int fd;
	size_t sock_addr_size;
	struct sockaddr_un * addr;
	struct ustcomm_sock *sock;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(fd == -1) {
		perror("socket");
		return NULL;
	}

	addr = create_sock_addr(name, &sock_addr_size);
	if (addr == NULL) {
		ERR("allocating addr, UST thread bailing");
		goto close_sock;
	}

	result = access(name, F_OK);
	if(result == 0) {
		/* file exists */
		result = unlink(name);
		if(result == -1) {
			perror("unlink of socket file");
			goto free_addr;
		}
		DBG("socket already exists; overwriting");
	}

	result = bind(fd, (struct sockaddr *)addr, sock_addr_size);
	if(result == -1) {
		perror("bind");
		goto free_addr;
	}

	result = listen(fd, 1);
	if(result == -1) {
		perror("listen");
		goto free_addr;
	}

	sock = ustcomm_init_sock(fd, epoll_fd, NULL);
	if (!sock) {
		ERR("failed to create ustcomm_sock");
		goto free_addr;
	}

	free(addr);

	return sock;

free_addr:
	free(addr);
close_sock:
	close(fd);

	return NULL;
}

/*
 *  ustcomm_del_named_sock
 *
 *  Delete named socket
 */
void ustcomm_del_named_sock(struct ustcomm_sock *sock, int keep_socket_file)
{
	int result, fd;
	struct stat st;
	struct sockaddr dummy;
	struct sockaddr_un *sockaddr = NULL;
	int alloc_size;

	fd = sock->fd;

	if(!keep_socket_file) {

		/* Get the socket name */
		alloc_size = sizeof(dummy);
		if (getsockname(fd, &dummy, (socklen_t *)&alloc_size) < 0) {
			perror("getsockname failed");
			goto del_sock;
		}

		sockaddr = malloc(alloc_size);
		if (!sockaddr) {
			ERR("failed to allocate sockaddr");
			goto del_sock;
		}

		if (getsockname(fd, sockaddr, (socklen_t *)&alloc_size) < 0) {
			perror("getsockname failed");
			goto free_sockaddr;
		}

		/* Destroy socket */
		result = stat(sockaddr->sun_path, &st);
		if(result < 0) {
			ERR("stat (%s)", sockaddr->sun_path);
			goto free_sockaddr;
		}

		/* Paranoid check before deleting. */
		result = S_ISSOCK(st.st_mode);
		if(!result) {
			ERR("The socket we are about to delete is not a socket.");
			goto free_sockaddr;
		}

		result = unlink(sockaddr->sun_path);
		if(result < 0) {
			perror("unlink");
		}
	}

free_sockaddr:
	free(sockaddr);

del_sock:
	ustcomm_del_sock(sock, keep_socket_file);
}

/*
 *  ustcomm_recv_alloc
 *
 *  Receive data and allocate data reception buffers.
 */
int ustcomm_recv_alloc(int sock, struct ustcomm_header *header, char **data)
{
	int result;
	struct ustcomm_header peek_header;
	struct iovec iov[2];
	struct msghdr msg;

	/* Just to make the caller fail hard */
	*data = NULL;

	result = recv(sock, &peek_header, sizeof(peek_header), MSG_PEEK | MSG_WAITALL);
	if (result <= 0) {
		if(errno == ECONNRESET) {
			return 0;
		} else if (errno == EINTR) {
			return -1;
		} else if (result < 0) {
			perror("recv");
			return -1;
		}
		return 0;
	}

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (char *)header;
	iov[0].iov_len = sizeof(struct ustcomm_header);

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if (peek_header.size) {
		*data = malloc(peek_header.size);
		if (!*data) {
			return -ENOMEM;
		}

		iov[1].iov_base = *data;
		iov[1].iov_len = peek_header.size;

		msg.msg_iovlen++;
	}

	result = recvmsg(sock, &msg, MSG_WAITALL);
	if (result < 0) {
		free(*data);
		perror("recvmsg failed");
	}

	return result;
}

/*
 *  ustcomm_recv_fd
 *
 *  Receive data from fd.
 *  returns 1 to indicate a message was received
 *  returns 0 to indicate no message was received (end of stream)
 *  returns -1 to indicate an error
 */
int ustcomm_recv_fd(int sock, struct ustcomm_header *header, char *data, int *fd)
{
	int result;
	struct ustcomm_header peek_header;
	struct iovec iov[2];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];

	result = recv(sock, &peek_header, sizeof(peek_header), MSG_PEEK | MSG_WAITALL);
	if (result <= 0) {
		if(errno == ECONNRESET) {
			return 0;
		} else if (errno == EINTR) {
			return -1;
		} else if (result < 0) {
			perror("recv");
			return -1;
		}
		return 0;
	}

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (char *)header;
	iov[0].iov_len = sizeof(struct ustcomm_header);

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if (peek_header.size && data) {
		if (peek_header.size < 0 ||
			peek_header.size > USTCOMM_DATA_SIZE) {
			ERR("big peek header! %ld", peek_header.size);
			return 0;
		}

		iov[1].iov_base = data;
		iov[1].iov_len = peek_header.size;

		msg.msg_iovlen++;
	}

	if (fd && peek_header.fd_included) {
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);
	}

	result = recvmsg(sock, &msg, MSG_WAITALL);
	if (result <= 0) {
		if (result < 0) {
			perror("recvmsg failed");
		}
		return result;
	}

	if (fd && peek_header.fd_included) {
		cmsg = CMSG_FIRSTHDR(&msg);
		result = 0;
		while (cmsg != NULL) {
			if (cmsg->cmsg_level == SOL_SOCKET
				&& cmsg->cmsg_type  == SCM_RIGHTS) {
				*fd = *(int *) CMSG_DATA(cmsg);
				result = 1;
				break;
			}
			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}
		if (!result) {
			ERR("Failed to receive file descriptor\n");
		}
	}

	return 1;
}

/*
 *  ustcomm_recv
 *
 *  Recv wrapper
 */
int ustcomm_recv(int sock, struct ustcomm_header *header, char *data)
{
	return ustcomm_recv_fd(sock, header, data, NULL);
}

/*
 *  ustcomm_send_fd
 *
 *  Send data to fd.
 */
int ustcomm_send_fd(int sock, const struct ustcomm_header *header,
		const char *data, int *fd)
{
	struct iovec iov[2];
	struct msghdr msg;
	int result;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (char *)header;
	iov[0].iov_len = sizeof(struct ustcomm_header);

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if (header->size && data) {
		iov[1].iov_base = (char *)data;
		iov[1].iov_len = header->size;

		msg.msg_iovlen++;

	}

	if (fd && header->fd_included) {
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		*(int *) CMSG_DATA(cmsg) = *fd;
		msg.msg_controllen = cmsg->cmsg_len;
	}

	result = sendmsg(sock, &msg, MSG_NOSIGNAL);
	if (result < 0 && errno != EPIPE) {
		perror("sendmsg failed");
	}
	return result;
}

/*
 *  ustcomm_send
 *
 *  Send wrapper
 */
int ustcomm_send(int sock, const struct ustcomm_header *header, const char *data)
{
	return ustcomm_send_fd(sock, header, data, NULL);
}

/*
 *  ustcomm_req
 *
 *  Do a request to the libust socket which means sending data and
 *  receiving data.
 */
int ustcomm_req(int sock,
		const struct ustcomm_header *req_header,
		const char *req_data,
		struct ustcomm_header *res_header,
		char *res_data)
{
	int result;

	result = ustcomm_send(sock, req_header, req_data);
	if ( result <= 0) {
		return result;
	}

	return ustcomm_recv(sock, res_header, res_data);
}

/*
 *  ustcomm_connect_path
 *
 *  Connect to an fd.
 *  Return value:
 *  0: success
 * -1: error
 */
int ustcomm_connect_path(const char *name, int *connection_fd)
{
	int result, fd;
	size_t sock_addr_size;
	struct sockaddr_un *addr;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(fd == -1) {
		perror("socket");
		return -1;
	}

	addr = create_sock_addr(name, &sock_addr_size);
	if (addr == NULL) {
		ERR("allocating addr failed");
		goto close_sock;
	}

	result = connect(fd, (struct sockaddr *)addr, sock_addr_size);
	if(result == -1) {
		perror("ustcomm connect path");
		goto free_sock_addr;
	}

	*connection_fd = fd;

	free(addr);

	return 0;

free_sock_addr:
	free(addr);
close_sock:
	close(fd);

	return -1;
}

/*
 *  ustcomm_user_sock_dir
 *
 *  Returns the current users socket directory, must be freed.
 */
char *ustcomm_user_sock_dir(void)
{
	int result;
	char *sock_dir = NULL;

	result = asprintf(&sock_dir, "/tmp/ust-app-socks/");
	if (result < 0) {
		ERR("string overflow allocating directory name");
		return NULL;
	}

	return sock_dir;
}

/*
 *  ustcomm_pid_st_mtime
 *
 *  Return time of the process pid creation.
 */
time_t ustcomm_pid_st_mtime(pid_t pid)
{
	struct stat proc_stat;
	char proc_name[PATH_MAX];

	if (snprintf(proc_name, PATH_MAX - 1, "/proc/%ld", (long) pid) < 0) {
		return 0;
	}

	if (stat(proc_name, &proc_stat)) {
		return 0;
	}

	return proc_stat.st_mtime;
}

/*
 *  ustcomm_connect_app
 *
 *  Connect to libust application using the pid.
 */
int ustcomm_connect_app(pid_t pid, int *app_fd)
{
	*app_fd = 0;

	if (geteuid()) {
		return connect_app_non_root(pid, app_fd);
	} else {
		return connect_app_root(pid, app_fd);
	}

}

/*
 *  ustcomm_print_data
 *
 *  Print data in a data_field.
 */
char *ustcomm_print_data(char *data_field, int field_size,
		int *offset, const char *format, ...)
{
	va_list args;
	int count, limit;
	char *ptr = USTCOMM_POISON_PTR;

	limit = field_size - *offset;
	va_start(args, format);
	count = vsnprintf(&data_field[*offset], limit, format, args);
	va_end(args);

	if (count < limit && count > -1) {
		ptr = NULL + *offset;
		*offset = *offset + count + 1;
	}

	return ptr;
}

/*
 *  ustcomm_restore_ptr
 */
char *ustcomm_restore_ptr(char *ptr, char *data_field, int data_field_size)
{
	if ((unsigned long)ptr > data_field_size || ptr == USTCOMM_POISON_PTR) {
		return NULL;
	}

	return data_field + (long)ptr;
}

/*
 *  ustcomm_pack_single_field
 */
int ustcomm_pack_single_field(struct ustcomm_header *header,
		struct ustcomm_single_field *single_field,
		const char *string)
{
	int offset = 0;

	single_field->field = ustcomm_print_data(single_field->data,
			sizeof(single_field->data),
			&offset,
			string);

	if (single_field->field == USTCOMM_POISON_PTR) {
		return -ENOMEM;
	}

	header->size = COMPUTE_MSG_SIZE(single_field, offset);

	return 0;
}

/*
 *  ustcomm_unpack_single_field
 */
int ustcomm_unpack_single_field(struct ustcomm_single_field *single_field)
{
	single_field->field = ustcomm_restore_ptr(single_field->field,
			single_field->data,
			sizeof(single_field->data));
	if (!single_field->field) {
		return -EINVAL;
	}

	return 0;
}

/*
 *  ustcomm_pack_channel_info
 */
int ustcomm_pack_channel_info(struct ustcomm_header *header,
		struct ustcomm_channel_info *ch_inf, const char *trace, const char *channel)
{
	int offset = 0;

	ch_inf->trace = ustcomm_print_data(ch_inf->data,
			sizeof(ch_inf->data), &offset, trace);

	if (ch_inf->trace == USTCOMM_POISON_PTR) {
		return -ENOMEM;
	}

	ch_inf->channel = ustcomm_print_data(ch_inf->data,
					sizeof(ch_inf->data), &offset, channel);

	if (ch_inf->channel == USTCOMM_POISON_PTR) {
		return -ENOMEM;
	}

	header->size = COMPUTE_MSG_SIZE(ch_inf, offset);

	return 0;
}

/*
 *  ustcomm_unpack_channel_info
 */
int ustcomm_unpack_channel_info(struct ustcomm_channel_info *ch_inf)
{
	ch_inf->trace = ustcomm_restore_ptr(ch_inf->trace,
			ch_inf->data, sizeof(ch_inf->data));
	if (!ch_inf->trace) {
		return -EINVAL;
	}

	ch_inf->channel = ustcomm_restore_ptr(ch_inf->channel,
			ch_inf->data, sizeof(ch_inf->data));
	if (!ch_inf->channel) {
		return -EINVAL;
	}

	return 0;
}

/*
 *  ustcomm_pack_buffer_info
 */
int ustcomm_pack_buffer_info(struct ustcomm_header *header,
		struct ustcomm_buffer_info *buf_inf,
		const char *trace, const char *channel, int channel_cpu)
{
	int offset = 0;

	buf_inf->trace = ustcomm_print_data(buf_inf->data,
			sizeof(buf_inf->data), &offset, trace);

	if (buf_inf->trace == USTCOMM_POISON_PTR) {
		return -ENOMEM;
	}

	buf_inf->channel = ustcomm_print_data(buf_inf->data,
			sizeof(buf_inf->data), &offset, channel);

	if (buf_inf->channel == USTCOMM_POISON_PTR) {
		return -ENOMEM;
	}

	buf_inf->ch_cpu = channel_cpu;

	header->size = COMPUTE_MSG_SIZE(buf_inf, offset);

	return 0;
}

/*
 *  ustcomm_unpack_buffer_info
 */
int ustcomm_unpack_buffer_info(struct ustcomm_buffer_info *buf_inf)
{
	buf_inf->trace = ustcomm_restore_ptr(buf_inf->trace,
			buf_inf->data, sizeof(buf_inf->data));
	if (!buf_inf->trace) {
		return -EINVAL;
	}

	buf_inf->channel = ustcomm_restore_ptr(buf_inf->channel,
			buf_inf->data, sizeof(buf_inf->data));
	if (!buf_inf->channel) {
		return -EINVAL;
	}

	return 0;
}

/*
 *  ustcomm_pack_ust_marker_info
 */
int ustcomm_pack_ust_marker_info(struct ustcomm_header *header,
			struct ustcomm_ust_marker_info *ust_marker_inf,
			const char *trace, const char *channel, const char *ust_marker)
{
	int offset = 0;

	ust_marker_inf->trace = ustcomm_print_data(ust_marker_inf->data,
			sizeof(ust_marker_inf->data), &offset, trace);

	if (ust_marker_inf->trace == USTCOMM_POISON_PTR) {
		return -ENOMEM;
	}


	ust_marker_inf->channel = ustcomm_print_data(ust_marker_inf->data,
			sizeof(ust_marker_inf->data), &offset, channel);

	if (ust_marker_inf->channel == USTCOMM_POISON_PTR) {
		return -ENOMEM;
	}


	ust_marker_inf->ust_marker = ustcomm_print_data(ust_marker_inf->data,
			sizeof(ust_marker_inf->data), &offset, ust_marker);

	if (ust_marker_inf->ust_marker == USTCOMM_POISON_PTR) {
		return -ENOMEM;
	}

	header->size = COMPUTE_MSG_SIZE(ust_marker_inf, offset);

	return 0;
}

/*
 *  ustcomm_unpack_ust_marker_info
 */
int ustcomm_unpack_ust_marker_info(struct ustcomm_ust_marker_info *ust_marker_inf)
{
	ust_marker_inf->trace = ustcomm_restore_ptr(ust_marker_inf->trace,
						ust_marker_inf->data,
						sizeof(ust_marker_inf->data));
	if (!ust_marker_inf->trace) {
		return -EINVAL;
	}

	ust_marker_inf->channel = ustcomm_restore_ptr(ust_marker_inf->channel,
			ust_marker_inf->data, sizeof(ust_marker_inf->data));
	if (!ust_marker_inf->channel) {
		return -EINVAL;
	}

	ust_marker_inf->ust_marker = ustcomm_restore_ptr(ust_marker_inf->ust_marker,
			ust_marker_inf->data, sizeof(ust_marker_inf->data));
	if (!ust_marker_inf->ust_marker) {
		return -EINVAL;
	}

	return 0;
}

