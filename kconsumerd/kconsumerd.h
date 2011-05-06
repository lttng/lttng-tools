/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#ifndef _LTT_KCONSUMERD_H
#define _LTT_KCONSUMERD_H

/* timeout of 1s on poll to ensure the fd list is updated when needed */
#define POLL_TIMEOUT 1000

struct ltt_kconsumerd_fd_list {
	struct cds_list_head head;
};

/*
 * Internal representation of the FDs,
 * sessiond_fd is used to identify uniquely a fd
 */
struct ltt_kconsumerd_fd {
	struct cds_list_head list;
	int sessiond_fd; /* used to identify uniquely a fd with sessiond */
	int consumerd_fd; /* fd to consume */
	int out_fd; /* output file to write the data */
	off_t out_fd_offset; /* write position in the output file descriptor */
	char path_name[PATH_MAX]; /* tracefile name */
	enum lttcomm_kconsumerd_fd_state state;
	unsigned long max_sb_size; /* the subbuffer size for this channel */
};

#endif /* _LTT_KCONSUMERD_H */
