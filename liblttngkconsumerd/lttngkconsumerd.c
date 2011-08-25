/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <lttng-kernel-ctl.h>
#include <lttng-sessiond-comm.h>
#include <lttng/lttng-kconsumerd.h>
#include <lttngerr.h>

static struct lttng_kconsumerd_global_data {
	/*
	 * kconsumerd_data.lock protects kconsumerd_data.fd_list,
	 * kconsumerd_data.fds_count, and kconsumerd_data.need_update. It ensures
	 * the count matches the number of items in the fd_list. It ensures the
	 * list updates *always* trigger an fd_array update (therefore need to make
	 * list update vs kconsumerd_data.need_update flag update atomic, and also
	 * flag read, fd array and flag clear atomic).
	 */
	pthread_mutex_t lock;
	/*
	 * Number of element for the list below. Protected by kconsumerd_data.lock.
	 */
	unsigned int fds_count;
	/*
	 * List of FDs. Protected by kconsumerd_data.lock.
	 */
	struct lttng_kconsumerd_fd_list fd_list;
	/*
	 * Flag specifying if the local array of FDs needs update in the poll
	 * function. Protected by kconsumerd_data.lock.
	 */
	unsigned int need_update;
} kconsumerd_data = {
	.fd_list.head = CDS_LIST_HEAD_INIT(kconsumerd_data.fd_list.head),
	.fds_count = 0,
	.need_update = 1,
};

/* timeout parameter, to control the polling thread grace period. */
static int kconsumerd_poll_timeout = -1;

/*
 * Flag to inform the polling thread to quit when all fd hung up. Updated by
 * the kconsumerd_thread_receive_fds when it notices that all fds has hung up.
 * Also updated by the signal handler (kconsumerd_should_exit()). Read by the
 * polling threads.
 */
static volatile int kconsumerd_quit = 0;

/*
 * Find a session fd in the global list. The kconsumerd_data.lock must be
 * locked during this call.
 *
 * Return 1 if found else 0.
 */
static int kconsumerd_find_session_fd(int fd)
{
	struct lttng_kconsumerd_fd *iter;

	cds_list_for_each_entry(iter, &kconsumerd_data.fd_list.head, list) {
		if (iter->sessiond_fd == fd) {
			DBG("Duplicate session fd %d", fd);
			return 1;
		}
	}

	return 0;
}

/*
 * Remove a fd from the global list protected by a mutex.
 */
static void kconsumerd_del_fd(struct lttng_kconsumerd_fd *lcf)
{
	int ret;
	pthread_mutex_lock(&kconsumerd_data.lock);
	cds_list_del(&lcf->list);
	if (kconsumerd_data.fds_count > 0) {
		kconsumerd_data.fds_count--;
		if (lcf != NULL) {
			if (lcf->mmap_base != NULL) {
				ret = munmap(lcf->mmap_base, lcf->mmap_len);
				if (ret != 0) {
					perror("munmap");
				}
			}
			if (lcf->out_fd != 0) {
				close(lcf->out_fd);
			}
			close(lcf->consumerd_fd);
			free(lcf);
			lcf = NULL;
		}
	}
	kconsumerd_data.need_update = 1;
	pthread_mutex_unlock(&kconsumerd_data.lock);
}

/*
 * Create a struct lttcomm_kconsumerd_msg from the
 * information received on the receiving socket
 */
struct lttng_kconsumerd_fd *kconsumerd_allocate_fd(
		struct lttcomm_kconsumerd_msg *buf,
		int consumerd_fd)
{
	struct lttng_kconsumerd_fd *tmp_fd;

	tmp_fd = malloc(sizeof(struct lttng_kconsumerd_fd));
	if (tmp_fd == NULL) {
		perror("malloc struct lttng_kconsumerd_fd");
		goto end;
	}

	tmp_fd->sessiond_fd = buf->fd;
	tmp_fd->consumerd_fd = consumerd_fd;
	tmp_fd->state = buf->state;
	tmp_fd->max_sb_size = buf->max_sb_size;
	tmp_fd->out_fd = 0;
	tmp_fd->out_fd_offset = 0;
	tmp_fd->mmap_len = 0;
	tmp_fd->mmap_base = NULL;
	tmp_fd->output = buf->output;
	strncpy(tmp_fd->path_name, buf->path_name, PATH_MAX);
	tmp_fd->path_name[PATH_MAX - 1] = '\0';
	DBG("Allocated %s (sessiond_fd %d, consumerd_fd %d, out_fd %d)",
			tmp_fd->path_name, tmp_fd->sessiond_fd,
			tmp_fd->consumerd_fd, tmp_fd->out_fd);

end:
	return tmp_fd;
}

/*
 * Add a fd to the global list protected by a mutex.
 */
static int kconsumerd_add_fd(struct lttng_kconsumerd_fd *tmp_fd)
{
	int ret;

	pthread_mutex_lock(&kconsumerd_data.lock);
	/* Check if already exist */
	ret = kconsumerd_find_session_fd(tmp_fd->sessiond_fd);
	if (ret == 1) {
		goto end;
	}
	cds_list_add(&tmp_fd->list, &kconsumerd_data.fd_list.head);
	kconsumerd_data.fds_count++;
	kconsumerd_data.need_update = 1;

end:
	pthread_mutex_unlock(&kconsumerd_data.lock);
	return ret;
}

/*
 * Update a fd according to what we just received.
 */
static void kconsumerd_change_fd_state(int sessiond_fd,
		enum lttng_kconsumerd_fd_state state)
{
	struct lttng_kconsumerd_fd *iter;

	pthread_mutex_lock(&kconsumerd_data.lock);
	cds_list_for_each_entry(iter, &kconsumerd_data.fd_list.head, list) {
		if (iter->sessiond_fd == sessiond_fd) {
			iter->state = state;
			break;
		}
	}
	kconsumerd_data.need_update = 1;
	pthread_mutex_unlock(&kconsumerd_data.lock);
}

/*
 * Allocate the pollfd structure and the local view of the out fds to avoid
 * doing a lookup in the linked list and concurrency issues when writing is
 * needed. Called with kconsumerd_data.lock held.
 *
 * Returns the number of fds in the structures.
 */
static int kconsumerd_update_poll_array(
		struct lttng_kconsumerd_local_data *ctx, struct pollfd **pollfd,
		struct lttng_kconsumerd_fd **local_kconsumerd_fd)
{
	struct lttng_kconsumerd_fd *iter;
	int i = 0;

	DBG("Updating poll fd array");
	cds_list_for_each_entry(iter, &kconsumerd_data.fd_list.head, list) {
		if (iter->state == ACTIVE_FD) {
			DBG("Active FD %d", iter->consumerd_fd);
			(*pollfd)[i].fd = iter->consumerd_fd;
			(*pollfd)[i].events = POLLIN | POLLPRI;
			local_kconsumerd_fd[i] = iter;
			i++;
		}
	}

	/*
	 * Insert the kconsumerd_poll_pipe at the end of the array and don't
	 * increment i so nb_fd is the number of real FD.
	 */
	(*pollfd)[i].fd = ctx->kconsumerd_poll_pipe[0];
	(*pollfd)[i].events = POLLIN;
	return i;
}

/*
 * Receives an array of file descriptors and the associated structures
 * describing each fd (path name).
 *
 * Returns the size of received data
 */
static int kconsumerd_consumerd_recv_fd(
		struct lttng_kconsumerd_local_data *ctx, int sfd,
		struct pollfd *kconsumerd_sockpoll, int size,
		enum lttng_kconsumerd_command cmd_type)
{
	struct iovec iov[1];
	int ret = 0, i, tmp2;
	struct cmsghdr *cmsg;
	int nb_fd;
	char recv_fd[CMSG_SPACE(sizeof(int))];
	struct lttcomm_kconsumerd_msg lkm;
	struct lttng_kconsumerd_fd *new_fd;

	/* the number of fds we are about to receive */
	nb_fd = size / sizeof(struct lttcomm_kconsumerd_msg);

	/*
	 * nb_fd is the number of fds we receive. One fd per recvmsg.
	 */
	for (i = 0; i < nb_fd; i++) {
		struct msghdr msg = { 0 };

		/* Prepare to receive the structures */
		iov[0].iov_base = &lkm;
		iov[0].iov_len = sizeof(lkm);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;

		msg.msg_control = recv_fd;
		msg.msg_controllen = sizeof(recv_fd);

		DBG("Waiting to receive fd");
		if (lttng_kconsumerd_poll_socket(kconsumerd_sockpoll) < 0) {
			goto end;
		}

		if ((ret = recvmsg(sfd, &msg, 0)) < 0) {
			perror("recvmsg");
			continue;
		}

		if (ret != (size / nb_fd)) {
			ERR("Received only %d, expected %d", ret, size);
			lttng_kconsumerd_send_error(ctx, KCONSUMERD_ERROR_RECV_FD);
			goto end;
		}

		cmsg = CMSG_FIRSTHDR(&msg);
		if (!cmsg) {
			ERR("Invalid control message header");
			ret = -1;
			lttng_kconsumerd_send_error(ctx, KCONSUMERD_ERROR_RECV_FD);
			goto end;
		}

		/* if we received fds */
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			switch (cmd_type) {
				case ADD_STREAM:
					DBG("kconsumerd_add_fd %s (%d)", lkm.path_name,
							((int *) CMSG_DATA(cmsg))[0]);

					new_fd = kconsumerd_allocate_fd(&lkm, ((int *) CMSG_DATA(cmsg))[0]);
					if (new_fd == NULL) {
						lttng_kconsumerd_send_error(ctx, KCONSUMERD_OUTFD_ERROR);
						goto end;
					}

					if (ctx->on_recv_fd != NULL) {
						ret = ctx->on_recv_fd(new_fd);
						if (ret == 0) {
							kconsumerd_add_fd(new_fd);
						} else if (ret < 0) {
							goto end;
						}
					} else {
						kconsumerd_add_fd(new_fd);
					}
					break;
				case UPDATE_STREAM:
					if (ctx->on_update_fd != NULL) {
						ret = ctx->on_update_fd(lkm.fd, lkm.state);
						if (ret == 0) {
							kconsumerd_change_fd_state(lkm.fd, lkm.state);
						} else if (ret < 0) {
							goto end;
						}
					} else {
						kconsumerd_change_fd_state(lkm.fd, lkm.state);
					}
					break;
				default:
					break;
			}
			/* signal the poll thread */
			tmp2 = write(ctx->kconsumerd_poll_pipe[1], "4", 1);
			if (tmp2 < 0) {
				perror("write kconsumerd poll");
			}
		} else {
			ERR("Didn't received any fd");
			lttng_kconsumerd_send_error(ctx, KCONSUMERD_ERROR_RECV_FD);
			ret = -1;
			goto end;
		}
	}

end:
	return ret;
}

/*
 * Set the error socket.
 */
void lttng_kconsumerd_set_error_sock(
		struct lttng_kconsumerd_local_data *ctx, int sock)
{
	ctx->kconsumerd_error_socket = sock;
}

/*
 * Set the command socket path.
 */

void lttng_kconsumerd_set_command_sock_path(
		struct lttng_kconsumerd_local_data *ctx, char *sock)
{
	ctx->kconsumerd_command_sock_path = sock;
}

static void lttng_kconsumerd_sync_trace_file(
		struct lttng_kconsumerd_fd *kconsumerd_fd, off_t orig_offset)
{
	int outfd = kconsumerd_fd->out_fd;
	/*
	 * This does a blocking write-and-wait on any page that belongs to the
	 * subbuffer prior to the one we just wrote.
	 * Don't care about error values, as these are just hints and ways to
	 * limit the amount of page cache used.
	 */
	if (orig_offset >= kconsumerd_fd->max_sb_size) {
		sync_file_range(outfd, orig_offset - kconsumerd_fd->max_sb_size,
				kconsumerd_fd->max_sb_size,
				SYNC_FILE_RANGE_WAIT_BEFORE
				| SYNC_FILE_RANGE_WRITE
				| SYNC_FILE_RANGE_WAIT_AFTER);
		/*
		 * Give hints to the kernel about how we access the file:
		 * POSIX_FADV_DONTNEED : we won't re-access data in a near future after
		 * we write it.
		 *
		 * We need to call fadvise again after the file grows because the
		 * kernel does not seem to apply fadvise to non-existing parts of the
		 * file.
		 *
		 * Call fadvise _after_ having waited for the page writeback to
		 * complete because the dirty page writeback semantic is not well
		 * defined. So it can be expected to lead to lower throughput in
		 * streaming.
		 */
		posix_fadvise(outfd, orig_offset - kconsumerd_fd->max_sb_size,
				kconsumerd_fd->max_sb_size, POSIX_FADV_DONTNEED);
	}
}


/*
 * Mmap the ring buffer, read it and write the data to the tracefile.
 *
 * Returns the number of bytes written
 */
int lttng_kconsumerd_on_read_subbuffer_mmap(
		struct lttng_kconsumerd_local_data *ctx,
		struct lttng_kconsumerd_fd *kconsumerd_fd, unsigned long len)
{
	unsigned long mmap_offset;
	long ret = 0;
	off_t orig_offset = kconsumerd_fd->out_fd_offset;
	int fd = kconsumerd_fd->consumerd_fd;
	int outfd = kconsumerd_fd->out_fd;

	/* get the offset inside the fd to mmap */
	ret = kernctl_get_mmap_read_offset(fd, &mmap_offset);
	if (ret != 0) {
		ret = errno;
		perror("kernctl_get_mmap_read_offset");
		goto end;
	}

	while (len > 0) {
		ret = write(outfd, kconsumerd_fd->mmap_base + mmap_offset, len);
		if (ret >= len) {
			len = 0;
		} else if (ret < 0) {
			ret = errno;
			perror("Error in file write");
			goto end;
		}
		/* This won't block, but will start writeout asynchronously */
		sync_file_range(outfd, kconsumerd_fd->out_fd_offset, ret,
				SYNC_FILE_RANGE_WRITE);
		kconsumerd_fd->out_fd_offset += ret;
	}

	lttng_kconsumerd_sync_trace_file(kconsumerd_fd, orig_offset);

	goto end;

end:
	return ret;
}

/*
 * Splice the data from the ring buffer to the tracefile.
 *
 * Returns the number of bytes spliced.
 */
int lttng_kconsumerd_on_read_subbuffer_splice(
		struct lttng_kconsumerd_local_data *ctx,
		struct lttng_kconsumerd_fd *kconsumerd_fd, unsigned long len)
{
	long ret = 0;
	loff_t offset = 0;
	off_t orig_offset = kconsumerd_fd->out_fd_offset;
	int fd = kconsumerd_fd->consumerd_fd;
	int outfd = kconsumerd_fd->out_fd;

	while (len > 0) {
		DBG("splice chan to pipe offset %lu (fd : %d)",
				(unsigned long)offset, fd);
		ret = splice(fd, &offset, ctx->kconsumerd_thread_pipe[1], NULL, len,
				SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("splice chan to pipe ret %ld", ret);
		if (ret < 0) {
			ret = errno;
			perror("Error in relay splice");
			goto splice_error;
		}

		ret = splice(ctx->kconsumerd_thread_pipe[0], NULL, outfd, NULL, ret,
				SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("splice pipe to file %ld", ret);
		if (ret < 0) {
			ret = errno;
			perror("Error in file splice");
			goto splice_error;
		}
		len -= ret;
		/* This won't block, but will start writeout asynchronously */
		sync_file_range(outfd, kconsumerd_fd->out_fd_offset, ret,
				SYNC_FILE_RANGE_WRITE);
		kconsumerd_fd->out_fd_offset += ret;
	}
	lttng_kconsumerd_sync_trace_file(kconsumerd_fd, orig_offset);

	goto end;

splice_error:
	/* send the appropriate error description to sessiond */
	switch(ret) {
	case EBADF:
		lttng_kconsumerd_send_error(ctx, KCONSUMERD_SPLICE_EBADF);
		break;
	case EINVAL:
		lttng_kconsumerd_send_error(ctx, KCONSUMERD_SPLICE_EINVAL);
		break;
	case ENOMEM:
		lttng_kconsumerd_send_error(ctx, KCONSUMERD_SPLICE_ENOMEM);
		break;
	case ESPIPE:
		lttng_kconsumerd_send_error(ctx, KCONSUMERD_SPLICE_ESPIPE);
		break;
	}

end:
	return ret;
}

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumerd_take_snapshot(struct lttng_kconsumerd_local_data *ctx,
		struct lttng_kconsumerd_fd *kconsumerd_fd)
{
	int ret = 0;
	int infd = kconsumerd_fd->consumerd_fd;

	ret = kernctl_snapshot(infd);
	if (ret != 0) {
		ret = errno;
		perror("Getting sub-buffer snapshot.");
	}

	return ret;
}

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumerd_get_produced_snapshot(
		struct lttng_kconsumerd_local_data *ctx,
		struct lttng_kconsumerd_fd *kconsumerd_fd,
		unsigned long *pos)
{
	int ret;
	int infd = kconsumerd_fd->consumerd_fd;

	ret = kernctl_snapshot_get_produced(infd, pos);
	if (ret != 0) {
		ret = errno;
		perror("kernctl_snapshot_get_produced");
	}

	return ret;
}

/*
 * Poll on the should_quit pipe and the command socket return -1 on error and
 * should exit, 0 if data is available on the command socket
 */
int lttng_kconsumerd_poll_socket(struct pollfd *kconsumerd_sockpoll)
{
	int num_rdy;

	num_rdy = poll(kconsumerd_sockpoll, 2, -1);
	if (num_rdy == -1) {
		perror("Poll error");
		goto exit;
	}
	if (kconsumerd_sockpoll[0].revents == POLLIN) {
		DBG("kconsumerd_should_quit wake up");
		goto exit;
	}
	return 0;

exit:
	return -1;
}

/*
 * This thread polls the fds in the ltt_fd_list to consume the data and write
 * it to tracefile if necessary.
 */
void *lttng_kconsumerd_thread_poll_fds(void *data)
{
	int num_rdy, num_hup, high_prio, ret, i;
	struct pollfd *pollfd = NULL;
	/* local view of the fds */
	struct lttng_kconsumerd_fd **local_kconsumerd_fd = NULL;
	/* local view of kconsumerd_data.fds_count */
	int nb_fd = 0;
	char tmp;
	int tmp2;
	struct lttng_kconsumerd_local_data *ctx = data;


	local_kconsumerd_fd = malloc(sizeof(struct lttng_kconsumerd_fd));

	while (1) {
		high_prio = 0;
		num_hup = 0;

		/*
		 * the ltt_fd_list has been updated, we need to update our
		 * local array as well
		 */
		pthread_mutex_lock(&kconsumerd_data.lock);
		if (kconsumerd_data.need_update) {
			if (pollfd != NULL) {
				free(pollfd);
				pollfd = NULL;
			}
			if (local_kconsumerd_fd != NULL) {
				free(local_kconsumerd_fd);
				local_kconsumerd_fd = NULL;
			}

			/* allocate for all fds + 1 for the kconsumerd_poll_pipe */
			pollfd = malloc((kconsumerd_data.fds_count + 1) * sizeof(struct pollfd));
			if (pollfd == NULL) {
				perror("pollfd malloc");
				pthread_mutex_unlock(&kconsumerd_data.lock);
				goto end;
			}

			/* allocate for all fds + 1 for the kconsumerd_poll_pipe */
			local_kconsumerd_fd = malloc((kconsumerd_data.fds_count + 1) *
					sizeof(struct lttng_kconsumerd_fd));
			if (local_kconsumerd_fd == NULL) {
				perror("local_kconsumerd_fd malloc");
				pthread_mutex_unlock(&kconsumerd_data.lock);
				goto end;
			}
			ret = kconsumerd_update_poll_array(ctx, &pollfd, local_kconsumerd_fd);
			if (ret < 0) {
				ERR("Error in allocating pollfd or local_outfds");
				lttng_kconsumerd_send_error(ctx, KCONSUMERD_POLL_ERROR);
				pthread_mutex_unlock(&kconsumerd_data.lock);
				goto end;
			}
			nb_fd = ret;
			kconsumerd_data.need_update = 0;
		}
		pthread_mutex_unlock(&kconsumerd_data.lock);

		/* poll on the array of fds */
		DBG("polling on %d fd", nb_fd + 1);
		num_rdy = poll(pollfd, nb_fd + 1, kconsumerd_poll_timeout);
		DBG("poll num_rdy : %d", num_rdy);
		if (num_rdy == -1) {
			perror("Poll error");
			lttng_kconsumerd_send_error(ctx, KCONSUMERD_POLL_ERROR);
			goto end;
		} else if (num_rdy == 0) {
			DBG("Polling thread timed out");
			goto end;
		}

		/* No FDs and kconsumerd_quit, kconsumerd_cleanup the thread */
		if (nb_fd == 0 && kconsumerd_quit == 1) {
			goto end;
		}

		/*
		 * If the kconsumerd_poll_pipe triggered poll go
		 * directly to the beginning of the loop to update the
		 * array. We want to prioritize array update over
		 * low-priority reads.
		 */
		if (pollfd[nb_fd].revents == POLLIN) {
			DBG("kconsumerd_poll_pipe wake up");
			tmp2 = read(ctx->kconsumerd_poll_pipe[0], &tmp, 1);
			if (tmp2 < 0) {
				perror("read kconsumerd poll");
			}
			continue;
		}

		/* Take care of high priority channels first. */
		for (i = 0; i < nb_fd; i++) {
			switch(pollfd[i].revents) {
			case POLLERR:
				ERR("Error returned in polling fd %d.", pollfd[i].fd);
				kconsumerd_del_fd(local_kconsumerd_fd[i]);
				num_hup++;
				break;
			case POLLHUP:
				DBG("Polling fd %d tells it has hung up.", pollfd[i].fd);
				kconsumerd_del_fd(local_kconsumerd_fd[i]);
				num_hup++;
				break;
			case POLLNVAL:
				ERR("Polling fd %d tells fd is not open.", pollfd[i].fd);
				kconsumerd_del_fd(local_kconsumerd_fd[i]);
				num_hup++;
				break;
			case POLLPRI:
				DBG("Urgent read on fd %d", pollfd[i].fd);
				high_prio = 1;
				ret = ctx->on_buffer_ready(local_kconsumerd_fd[i]);
				/* it's ok to have an unavailable sub-buffer */
				if (ret == EAGAIN) {
					ret = 0;
				}
				break;
			}
		}

		/* If every buffer FD has hung up, we end the read loop here */
		if (nb_fd > 0 && num_hup == nb_fd) {
			DBG("every buffer FD has hung up\n");
			if (kconsumerd_quit == 1) {
				goto end;
			}
			continue;
		}

		/* Take care of low priority channels. */
		if (high_prio == 0) {
			for (i = 0; i < nb_fd; i++) {
				if (pollfd[i].revents == POLLIN) {
					DBG("Normal read on fd %d", pollfd[i].fd);
					ret = ctx->on_buffer_ready(local_kconsumerd_fd[i]);
					/* it's ok to have an unavailable subbuffer */
					if (ret == EAGAIN) {
						ret = 0;
					}
				}
			}
		}
	}
end:
	DBG("polling thread exiting");
	if (pollfd != NULL) {
		free(pollfd);
		pollfd = NULL;
	}
	if (local_kconsumerd_fd != NULL) {
		free(local_kconsumerd_fd);
		local_kconsumerd_fd = NULL;
	}
	return NULL;
}

/*
 * Initialise the necessary environnement :
 * - create a new context
 * - create the poll_pipe
 * - create the should_quit pipe (for signal handler)
 * - create the thread pipe (for splice)
 *
 * Takes a function pointer as argument, this function is called when data is
 * available on a buffer. This function is responsible to do the
 * kernctl_get_next_subbuf, read the data with mmap or splice depending on the
 * buffer configuration and then kernctl_put_next_subbuf at the end.
 *
 * Returns a pointer to the new context or NULL on error.
 */
struct lttng_kconsumerd_local_data *lttng_kconsumerd_create(
		int (*buffer_ready)(struct lttng_kconsumerd_fd *kconsumerd_fd),
		int (*recv_fd)(struct lttng_kconsumerd_fd *kconsumerd_fd),
		int (*update_fd)(int sessiond_fd, uint32_t state))
{
	int ret, i;
	struct lttng_kconsumerd_local_data *ctx;

	ctx = malloc(sizeof(struct lttng_kconsumerd_local_data));
	if (ctx == NULL) {
		perror("allocating context");
		goto error;
	}

	ctx->kconsumerd_error_socket = -1;
	/* assign the callbacks */
	ctx->on_buffer_ready = buffer_ready;
	ctx->on_recv_fd = recv_fd;
	ctx->on_update_fd = update_fd;

	ret = pipe(ctx->kconsumerd_poll_pipe);
	if (ret < 0) {
		perror("Error creating poll pipe");
		goto error_poll_pipe;
	}

	ret = pipe(ctx->kconsumerd_should_quit);
	if (ret < 0) {
		perror("Error creating recv pipe");
		goto error_quit_pipe;
	}

	ret = pipe(ctx->kconsumerd_thread_pipe);
	if (ret < 0) {
		perror("Error creating thread pipe");
		goto error_thread_pipe;
	}

	return ctx;


error_thread_pipe:
	for (i = 0; i < 2; i++) {
		int err;

		err = close(ctx->kconsumerd_should_quit[i]);
		assert(!err);
	}
error_quit_pipe:
	for (i = 0; i < 2; i++) {
		int err;

		err = close(ctx->kconsumerd_poll_pipe[i]);
		assert(!err);
	}
error_poll_pipe:
	free(ctx);
error:
	return NULL;
}

/*
 * Close all fds associated with the instance and free the context.
 */
void lttng_kconsumerd_destroy(struct lttng_kconsumerd_local_data *ctx)
{
	close(ctx->kconsumerd_error_socket);
	close(ctx->kconsumerd_thread_pipe[0]);
	close(ctx->kconsumerd_thread_pipe[1]);
	close(ctx->kconsumerd_poll_pipe[0]);
	close(ctx->kconsumerd_poll_pipe[1]);
	close(ctx->kconsumerd_should_quit[0]);
	close(ctx->kconsumerd_should_quit[1]);
	unlink(ctx->kconsumerd_command_sock_path);
	free(ctx);
	ctx = NULL;
}

/*
 * This thread listens on the consumerd socket and receives the file
 * descriptors from the session daemon.
 */
void *lttng_kconsumerd_thread_receive_fds(void *data)
{
	int sock, client_socket, ret;
	struct lttcomm_kconsumerd_header tmp;
	/*
	 * structure to poll for incoming data on communication socket avoids
	 * making blocking sockets.
	 */
	struct pollfd kconsumerd_sockpoll[2];
	struct lttng_kconsumerd_local_data *ctx = data;


	DBG("Creating command socket %s", ctx->kconsumerd_command_sock_path);
	unlink(ctx->kconsumerd_command_sock_path);
	client_socket = lttcomm_create_unix_sock(ctx->kconsumerd_command_sock_path);
	if (client_socket < 0) {
		ERR("Cannot create command socket");
		goto end;
	}

	ret = lttcomm_listen_unix_sock(client_socket);
	if (ret < 0) {
		goto end;
	}

	DBG("Sending ready command to ltt-sessiond");
	ret = lttng_kconsumerd_send_error(ctx, KCONSUMERD_COMMAND_SOCK_READY);
	/* return < 0 on error, but == 0 is not fatal */
	if (ret < 0) {
		ERR("Error sending ready command to ltt-sessiond");
		goto end;
	}

	ret = fcntl(client_socket, F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		perror("fcntl O_NONBLOCK");
		goto end;
	}

	/* prepare the FDs to poll : to client socket and the should_quit pipe */
	kconsumerd_sockpoll[0].fd = ctx->kconsumerd_should_quit[0];
	kconsumerd_sockpoll[0].events = POLLIN | POLLPRI;
	kconsumerd_sockpoll[1].fd = client_socket;
	kconsumerd_sockpoll[1].events = POLLIN | POLLPRI;

	if (lttng_kconsumerd_poll_socket(kconsumerd_sockpoll) < 0) {
		goto end;
	}
	DBG("Connection on client_socket");

	/* Blocking call, waiting for transmission */
	sock = lttcomm_accept_unix_sock(client_socket);
	if (sock <= 0) {
		WARN("On accept");
		goto end;
	}
	ret = fcntl(sock, F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		perror("fcntl O_NONBLOCK");
		goto end;
	}

	/* update the polling structure to poll on the established socket */
	kconsumerd_sockpoll[1].fd = sock;
	kconsumerd_sockpoll[1].events = POLLIN | POLLPRI;

	while (1) {
		if (lttng_kconsumerd_poll_socket(kconsumerd_sockpoll) < 0) {
			goto end;
		}
		DBG("Incoming fds on sock");

		/* We first get the number of fd we are about to receive */
		ret = lttcomm_recv_unix_sock(sock, &tmp,
				sizeof(struct lttcomm_kconsumerd_header));
		if (ret <= 0) {
			ERR("Communication interrupted on command socket");
			goto end;
		}
		if (tmp.cmd_type == STOP) {
			DBG("Received STOP command");
			goto end;
		}
		if (kconsumerd_quit) {
			DBG("kconsumerd_thread_receive_fds received quit from signal");
			goto end;
		}

		/* we received a command to add or update fds */
		ret = kconsumerd_consumerd_recv_fd(ctx, sock, kconsumerd_sockpoll,
				tmp.payload_size, tmp.cmd_type);
		if (ret < 0) {
			ERR("Receiving the FD, exiting");
			goto end;
		}
		DBG("received fds on sock");
	}

end:
	DBG("kconsumerd_thread_receive_fds exiting");

	/*
	 * when all fds have hung up, the polling thread
	 * can exit cleanly
	 */
	kconsumerd_quit = 1;

	/*
	 * 2s of grace period, if no polling events occur during
	 * this period, the polling thread will exit even if there
	 * are still open FDs (should not happen, but safety mechanism).
	 */
	kconsumerd_poll_timeout = LTTNG_KCONSUMERD_POLL_GRACE_PERIOD;

	/* wake up the polling thread */
	ret = write(ctx->kconsumerd_poll_pipe[1], "4", 1);
	if (ret < 0) {
		perror("poll pipe write");
	}
	return NULL;
}

/*
 * Close all the tracefiles and stream fds, should be called when all instances
 * are destroyed.
 */
void lttng_kconsumerd_cleanup(void)
{
	struct lttng_kconsumerd_fd *iter, *tmp;

	/*
	 * close all outfd. Called when there are no more threads
	 * running (after joining on the threads), no need to protect
	 * list iteration with mutex.
	 */
	cds_list_for_each_entry_safe(iter, tmp,
			&kconsumerd_data.fd_list.head, list) {
		kconsumerd_del_fd(iter);
	}
}

/*
 * Called from signal handler.
 */
void lttng_kconsumerd_should_exit(struct lttng_kconsumerd_local_data *ctx)
{
	int ret;
	kconsumerd_quit = 1;
	ret = write(ctx->kconsumerd_should_quit[1], "4", 1);
	if (ret < 0) {
		perror("write kconsumerd quit");
	}
}

/*
 * Send return code to the session daemon.
 * If the socket is not defined, we return 0, it is not a fatal error
 */
int lttng_kconsumerd_send_error(
		struct lttng_kconsumerd_local_data *ctx, int cmd)
{
	if (ctx->kconsumerd_error_socket > 0) {
		return lttcomm_send_unix_sock(ctx->kconsumerd_error_socket, &cmd,
				sizeof(enum lttcomm_sessiond_command));
	}

	return 0;
}
