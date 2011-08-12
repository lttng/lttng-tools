/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LIBLTTKCONSUMERD_H
#define _LIBLTTKCONSUMERD_H

#include <lttng-sessiond-comm.h>
#include "lttng-kconsumerd.h"

/*
 * When the receiving thread dies, we need to have a way to make
 * the polling thread exit eventually.
 * If all FDs hang up (normal case when the ltt-sessiond stops),
 * we can exit cleanly, but if there is a problem and for whatever
 * reason some FDs remain open, the consumer should still exit eventually.
 *
 * If the timeout is reached, it means that during this period
 * no events occurred on the FDs so we need to force an exit.
 * This case should not happen but it is a safety to ensure we won't block
 * the consumer indefinitely.
 *
 * The value of 2 seconds is an arbitrary choice.
 */
#define KCONSUMERD_POLL_GRACE_PERIOD 2000

struct kconsumerd_fd_list {
	struct cds_list_head head;
};

/*
 * Internal representation of the FDs,
 * sessiond_fd is used to identify uniquely a fd
 */
struct kconsumerd_fd {
	struct cds_list_head list;
	int sessiond_fd; /* used to identify uniquely a fd with sessiond */
	int consumerd_fd; /* fd to consume */
	int out_fd; /* output file to write the data */
	off_t out_fd_offset; /* write position in the output file descriptor */
	char path_name[PATH_MAX]; /* tracefile name */
	enum kconsumerd_fd_state state;
	unsigned long max_sb_size; /* the subbuffer size for this channel */
};

/*
 * kconsumerd_init(void)
 * initialise the necessary environnement :
 * - inform the polling thread to update the polling array
 * - create the poll_pipe
 * - create the should_quit pipe (for signal handler)
 * returns the return code of pipe, 0 on success, -1 on error
 */
int kconsumerd_init(void);

/*
 * kconsumerd_send_error
 * send return code to ltt-sessiond
 * returns the return code of sendmsg : the number of bytes transmitted
 * or -1 on error.
 */
int kconsumerd_send_error(enum lttcomm_return_code cmd);

/*
 * kconsumerd_poll_socket
 * Poll on the should_quit pipe and the command socket
 * return -1 on error and should exit, 0 if data is
 * available on the command socket
 */
int kconsumerd_poll_socket(struct pollfd *kconsumerd_sockpoll);

/*
 *  kconsumerd_thread_poll_fds
 *  This thread polls the fds in the ltt_fd_list to consume the data
 *  and write it to tracefile if necessary.
 */
void *kconsumerd_thread_poll_fds(void *data);

/*
 *  kconsumerd_thread_receive_fds
 *  This thread listens on the consumerd socket and
 *  receives the file descriptors from ltt-sessiond
 */
void *kconsumerd_thread_receive_fds(void *data);

/*
 * kconsumerd_should_exit
 * Called from signal handler to ensure a clean exit
 */
void kconsumerd_should_exit(void);

/*
 *  kconsumerd_cleanup
 *  Cleanup the daemon's socket on exit
 */
void kconsumerd_cleanup(void);

/*
 * kconsumerd_set_error_socket
 * Set the error socket for communication with a session daemon
 */
void kconsumerd_set_error_socket(int sock);

/*
 * kconsumerd_set_command_socket_path
 * Set the command socket path for communication with a session daemon
 */
void kconsumerd_set_command_socket_path(char *sock);

#endif /* _LIBLTTKCONSUMERD_H */
