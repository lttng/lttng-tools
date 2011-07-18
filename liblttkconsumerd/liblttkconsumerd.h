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

#include "lttng-kconsumerd.h"
#include "liblttsessiondcomm.h"

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

int kconsumerd_create_poll_pipe();
int kconsumerd_send_error(enum lttcomm_return_code cmd);
void *kconsumerd_thread_poll_fds(void *data);
void *kconsumerd_thread_receive_fds(void *data);
void kconsumerd_should_exit(void);
void kconsumerd_cleanup(void);
void kconsumerd_set_error_socket(int sock);
void kconsumerd_set_command_socket_path(char *sock);

#endif /* _LIBLTTKCONSUMERD_H */
