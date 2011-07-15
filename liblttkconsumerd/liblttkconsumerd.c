/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <urcu/list.h>

#include "libkernelctl.h"
#include "liblttkconsumerd.h"
#include "lttngerr.h"

static
struct kconsumerd_global_data {
	/*
	 * kconsumerd_data.lock protects kconsumerd_data.fd_list,
	 * kconsumerd_data.fds_count, and kconsumerd_data.need_update.  It
	 * ensures the count matches the number of items in the fd_list.
	 * It ensures the list updates *always* trigger an fd_array
	 * update (therefore need to make list update vs
	 * kconsumerd_data.need_update flag update atomic, and also flag
	 * read, fd array and flag clear atomic).
	 */
	pthread_mutex_t lock;
	/*
	 * Number of element for the list below.  Protected by
	 * kconsumerd_data.lock.
	 */
	unsigned int fds_count;
	/*
	 * List of FDs.  Protected by kconsumerd_data.lock.
	 */
	struct kconsumerd_fd_list fd_list;
	/*
	 * Flag specifying if the local array of FDs needs update in the
	 * poll function.  Protected by kconsumerd_data.lock.
	 */
	unsigned int need_update;
} kconsumerd_data = {
	.fd_list.head = CDS_LIST_HEAD_INIT(kconsumerd_data.fd_list.head),
	.need_update = 1,
};

/* communication with splice */
static int kconsumerd_thread_pipe[2];

/* pipe to wake the poll thread when necessary */
static int kconsumerd_poll_pipe[2];

/*
 * TODO: create a should_quit pipe to let the signal handler wake up the
 * fd receiver thread. It should be initialized before any signal can be
 * received by the library.
 */


/* timeout parameter, to control the polling thread grace period */
static int kconsumerd_poll_timeout = -1;

/* socket to communicate errors with sessiond */
static int kconsumerd_error_socket;

/* socket to exchange commands with sessiond */
static char *kconsumerd_command_sock_path;

/*
 * flag to inform the polling thread to quit when all fd hung up.
 * Updated by the kconsumerd_thread_receive_fds when it notices that all
 * fds has hung up. Also updated by the signal handler
 * (kconsumerd_should_exit()). Read by the polling threads.
 */
static volatile int kconsumerd_quit = 0;

/*
 * kconsumerd_set_error_socket
 *
 * Set the error socket
 */
void kconsumerd_set_error_socket(int sock)
{
	kconsumerd_error_socket = sock;
}

/*
 * kconsumerd_set_command_socket_path
 *
 * Set the command socket path
 */
void kconsumerd_set_command_socket_path(char *sock)
{
	kconsumerd_command_sock_path = sock;
}

/*
 * kconsumerd_find_session_fd
 *
 * Find a session fd in the global list.
 * The kconsumerd_data.lock must be locked during this call
 *
 * Return 1 if found else 0
 */
static int kconsumerd_find_session_fd(int fd)
{
	struct kconsumerd_fd *iter;

	cds_list_for_each_entry(iter, &kconsumerd_data.fd_list.head, list) {
		if (iter->sessiond_fd == fd) {
			DBG("Duplicate session fd %d", fd);
			pthread_mutex_unlock(&kconsumerd_data.lock);
			return 1;
		}
	}

	return 0;
}

/*
 * kconsumerd_del_fd
 *
 * Remove a fd from the global list protected by a mutex
 */
static void kconsumerd_del_fd(struct kconsumerd_fd *lcf)
{
	pthread_mutex_lock(&kconsumerd_data.lock);
	cds_list_del(&lcf->list);
	if (kconsumerd_data.fds_count > 0) {
		kconsumerd_data.fds_count--;
		if (lcf != NULL) {
			close(lcf->out_fd);
			close(lcf->consumerd_fd);
			free(lcf);
			lcf = NULL;
		}
	}
	kconsumerd_data.need_update = 1;
	pthread_mutex_unlock(&kconsumerd_data.lock);
}

/*
 * kconsumerd_add_fd
 *
 * Add a fd to the global list protected by a mutex
 */
static int kconsumerd_add_fd(struct lttcomm_kconsumerd_msg *buf, int consumerd_fd)
{
	int ret;
	struct kconsumerd_fd *tmp_fd;

	pthread_mutex_lock(&kconsumerd_data.lock);
	/* Check if already exist */
	ret = kconsumerd_find_session_fd(buf->fd);
	if (ret == 1) {
		goto end;
	}

	tmp_fd = malloc(sizeof(struct kconsumerd_fd));
	tmp_fd->sessiond_fd = buf->fd;
	tmp_fd->consumerd_fd = consumerd_fd;
	tmp_fd->state = buf->state;
	tmp_fd->max_sb_size = buf->max_sb_size;
	strncpy(tmp_fd->path_name, buf->path_name, PATH_MAX);

	/* Opening the tracefile in write mode */
	ret = open(tmp_fd->path_name,
			O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO);
	if (ret < 0) {
		ERR("Opening %s", tmp_fd->path_name);
		perror("open");
		goto end;
	}
	tmp_fd->out_fd = ret;
	tmp_fd->out_fd_offset = 0;

	DBG("Adding %s (%d, %d, %d)", tmp_fd->path_name,
			tmp_fd->sessiond_fd, tmp_fd->consumerd_fd, tmp_fd->out_fd);

	cds_list_add(&tmp_fd->list, &kconsumerd_data.fd_list.head);
	kconsumerd_data.fds_count++;
	kconsumerd_data.need_update = 1;
end:
	pthread_mutex_unlock(&kconsumerd_data.lock);
	return ret;
}

/*
 * kconsumerd_change_fd_state
 *
 * Update a fd according to what we just received
 */
static void kconsumerd_change_fd_state(int sessiond_fd,
		enum kconsumerd_fd_state state)
{
	struct kconsumerd_fd *iter;

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
 * kconsumerd_update_poll_array
 *
 * Allocate the pollfd structure and the local view of the out fds
 * to avoid doing a lookup in the linked list and concurrency issues
 * when writing is needed.
 * Returns the number of fds in the structures
 * Called with kconsumerd_data.lock held.
 */
static int kconsumerd_update_poll_array(struct pollfd **pollfd,
		struct kconsumerd_fd **local_kconsumerd_fd)
{
	struct kconsumerd_fd *iter;
	int i = 0;

	DBG("Updating poll fd array");

	cds_list_for_each_entry(iter, &kconsumerd_data.fd_list.head, list) {
		DBG("Inside for each");
		if (iter->state == ACTIVE_FD) {
			DBG("Active FD %d", iter->consumerd_fd);
			(*pollfd)[i].fd = iter->consumerd_fd;
			(*pollfd)[i].events = POLLIN | POLLPRI;
			local_kconsumerd_fd[i] = iter;
			i++;
		}
	}

	/*
	 * insert the kconsumerd_poll_pipe at the end of the array and don't
	 * increment i so nb_fd is the number of real FD
	 */
	(*pollfd)[i].fd = kconsumerd_poll_pipe[0];
	(*pollfd)[i].events = POLLIN;
	return i;
}


/*
 * kconsumerd_on_read_subbuffer_mmap
 *
 * mmap the ring buffer, read it and write the data to the tracefile.
 * Returns the number of bytes written
 */
static int kconsumerd_on_read_subbuffer_mmap(
		struct kconsumerd_fd *kconsumerd_fd, unsigned long len)
{
	unsigned long mmap_len, mmap_offset, padded_len, padding_len;
	char *mmap_base;
	char *padding = NULL;
	long ret = 0;
	off_t orig_offset = kconsumerd_fd->out_fd_offset;
	int fd = kconsumerd_fd->consumerd_fd;
	int outfd = kconsumerd_fd->out_fd;

	/* get the padded subbuffer size to know the padding required */
	ret = kernctl_get_padded_subbuf_size(fd, &padded_len);
	if (ret != 0) {
		ret = errno;
		perror("kernctl_get_padded_subbuf_size");
		goto end;
	}
	padding_len = padded_len - len;
	padding = malloc(padding_len * sizeof(char));
	memset(padding, '\0', padding_len);

	/* get the len of the mmap region */
	ret = kernctl_get_mmap_len(fd, &mmap_len);
	if (ret != 0) {
		ret = errno;
		perror("kernctl_get_mmap_len");
		goto end;
	}

	/* get the offset inside the fd to mmap */
	ret = kernctl_get_mmap_read_offset(fd, &mmap_offset);
	if (ret != 0) {
		ret = errno;
		perror("kernctl_get_mmap_read_offset");
		goto end;
	}

	mmap_base = mmap(NULL, mmap_len, PROT_READ, MAP_PRIVATE, fd, mmap_offset);
	if (mmap_base == MAP_FAILED) {
		perror("Error mmaping");
		ret = -1;
		goto end;
	}

	while (len > 0) {
		ret = write(outfd, mmap_base, len);
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

	/* once all the data is written, write the padding to disk */
	ret = write(outfd, padding, padding_len);
	if (ret < 0) {
		ret = errno;
		perror("Error writing padding to file");
		goto end;
	}

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
	goto end;

end:
	if (padding != NULL) {
		free(padding);
	}
	return ret;
}

/*
 * kconsumerd_on_read_subbuffer
 *
 * Splice the data from the ring buffer to the tracefile.
 * Returns the number of bytes spliced
 */
static int kconsumerd_on_read_subbuffer(
		struct kconsumerd_fd *kconsumerd_fd, unsigned long len)
{
	long ret = 0;
	loff_t offset = 0;
	off_t orig_offset = kconsumerd_fd->out_fd_offset;
	int fd = kconsumerd_fd->consumerd_fd;
	int outfd = kconsumerd_fd->out_fd;

	while (len > 0) {
		DBG("splice chan to pipe offset %lu (fd : %d)",
				(unsigned long)offset, fd);
		ret = splice(fd, &offset, kconsumerd_thread_pipe[1], NULL, len,
				SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("splice chan to pipe ret %ld", ret);
		if (ret < 0) {
			ret = errno;
			perror("Error in relay splice");
			goto splice_error;
		}

		ret = splice(kconsumerd_thread_pipe[0], NULL, outfd, NULL, ret,
				SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("splice pipe to file %ld", ret);
		if (ret < 0) {
			ret = errno;
			perror("Error in file splice");
			goto splice_error;
		}
		if (ret >= len) {
			len = 0;
		}
		/* This won't block, but will start writeout asynchronously */
		sync_file_range(outfd, kconsumerd_fd->out_fd_offset, ret,
				SYNC_FILE_RANGE_WRITE);
		kconsumerd_fd->out_fd_offset += ret;
	}

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
	goto end;

splice_error:
	/* send the appropriate error description to sessiond */
	switch(ret) {
	case EBADF:
		kconsumerd_send_error(KCONSUMERD_SPLICE_EBADF);
		break;
	case EINVAL:
		kconsumerd_send_error(KCONSUMERD_SPLICE_EINVAL);
		break;
	case ENOMEM:
		kconsumerd_send_error(KCONSUMERD_SPLICE_ENOMEM);
		break;
	case ESPIPE:
		kconsumerd_send_error(KCONSUMERD_SPLICE_ESPIPE);
		break;
	}

end:
	return ret;
}

/*
 * kconsumerd_read_subbuffer
 *
 * Consume data on a file descriptor and write it on a trace file
 */
static int kconsumerd_read_subbuffer(struct kconsumerd_fd *kconsumerd_fd)
{
	unsigned long len;
	int err;
	long ret = 0;
	int infd = kconsumerd_fd->consumerd_fd;

	DBG("In kconsumerd_read_subbuffer (infd : %d)", infd);
	/* Get the next subbuffer */
	err = kernctl_get_next_subbuf(infd);
	if (err != 0) {
		ret = errno;
		perror("Reserving sub buffer failed (everything is normal, "
				"it is due to concurrency)");
		goto end;
	}

	switch (DEFAULT_KERNEL_CHANNEL_OUTPUT) {
	case LTTNG_KERNEL_SPLICE:
		/* read the whole subbuffer */
		err = kernctl_get_padded_subbuf_size(infd, &len);
		if (err != 0) {
			ret = errno;
			perror("Getting sub-buffer len failed.");
			goto end;
		}

		/* splice the subbuffer to the tracefile */
		ret = kconsumerd_on_read_subbuffer(kconsumerd_fd, len);
		if (ret < 0) {
			/*
			 * display the error but continue processing to try
			 * to release the subbuffer
			 */
			ERR("Error splicing to tracefile");
		}
		break;
	case LTTNG_KERNEL_MMAP:
		/* read the used subbuffer size */
		err = kernctl_get_subbuf_size(infd, &len);
		if (err != 0) {
			ret = errno;
			perror("Getting sub-buffer len failed.");
			goto end;
		}
		/* write the subbuffer to the tracefile */
		ret = kconsumerd_on_read_subbuffer_mmap(kconsumerd_fd, len);
		if (ret < 0) {
			/*
			 * display the error but continue processing to try
			 * to release the subbuffer
			 */
			ERR("Error writing to tracefile");
		}
		break;
	default:
		ERR("Unknown output method");
		ret = -1;
	}

	err = kernctl_put_next_subbuf(infd);
	if (err != 0) {
		ret = errno;
		if (errno == EFAULT) {
			perror("Error in unreserving sub buffer\n");
		} else if (errno == EIO) {
			/* Should never happen with newer LTTng versions */
			perror("Reader has been pushed by the writer, last sub-buffer corrupted.");
		}
		goto end;
	}

end:
	return ret;
}

/*
 * kconsumerd_consumerd_recv_fd
 *
 * Receives an array of file descriptors and the associated
 * structures describing each fd (path name).
 * Returns the size of received data
 */
static int kconsumerd_consumerd_recv_fd(int sfd, int size,
		enum kconsumerd_command cmd_type)
{
	struct msghdr msg;
	struct iovec iov[1];
	int ret = 0, i, tmp2;
	struct cmsghdr *cmsg;
	int nb_fd;
	char recv_fd[CMSG_SPACE(sizeof(int))];
	struct lttcomm_kconsumerd_msg lkm;

	/* the number of fds we are about to receive */
	nb_fd = size / sizeof(struct lttcomm_kconsumerd_msg);

	for (i = 0; i < nb_fd; i++) {
		memset(&msg, 0, sizeof(msg));

		/* Prepare to receive the structures */
		iov[0].iov_base = &lkm;
		iov[0].iov_len = sizeof(lkm);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;

		msg.msg_control = recv_fd;
		msg.msg_controllen = sizeof(recv_fd);

		DBG("Waiting to receive fd");
		if ((ret = recvmsg(sfd, &msg, 0)) < 0) {
			perror("recvmsg");
			continue;
		}

		if (ret != (size / nb_fd)) {
			ERR("Received only %d, expected %d", ret, size);
			kconsumerd_send_error(KCONSUMERD_ERROR_RECV_FD);
			goto end;
		}

		cmsg = CMSG_FIRSTHDR(&msg);
		if (!cmsg) {
			ERR("Invalid control message header");
			ret = -1;
			kconsumerd_send_error(KCONSUMERD_ERROR_RECV_FD);
			goto end;
		}
		/* if we received fds */
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			switch (cmd_type) {
			case ADD_STREAM:
				DBG("kconsumerd_add_fd %s (%d)", lkm.path_name, (CMSG_DATA(cmsg)[0]));
				ret = kconsumerd_add_fd(&lkm, (CMSG_DATA(cmsg)[0]));
				if (ret < 0) {
					kconsumerd_send_error(KCONSUMERD_OUTFD_ERROR);
					goto end;
				}
				break;
			case UPDATE_STREAM:
				kconsumerd_change_fd_state(lkm.fd, lkm.state);
				break;
			default:
				break;
			}
			/* signal the poll thread */
			tmp2 = write(kconsumerd_poll_pipe[1], "4", 1);
		} else {
			ERR("Didn't received any fd");
			kconsumerd_send_error(KCONSUMERD_ERROR_RECV_FD);
			ret = -1;
			goto end;
		}
	}

end:
	return ret;
}

/*
 *  kconsumerd_thread_poll_fds
 *
 *  This thread polls the fds in the ltt_fd_list to consume the data
 *  and write it to tracefile if necessary.
 */
void *kconsumerd_thread_poll_fds(void *data)
{
	int num_rdy, num_hup, high_prio, ret, i;
	struct pollfd *pollfd = NULL;
	/* local view of the fds */
	struct kconsumerd_fd **local_kconsumerd_fd = NULL;
	/* local view of kconsumerd_data.fds_count */
	int nb_fd = 0;
	char tmp;
	int tmp2;

	ret = pipe(kconsumerd_thread_pipe);
	if (ret < 0) {
		perror("Error creating pipe");
		goto end;
	}

	local_kconsumerd_fd = malloc(sizeof(struct kconsumerd_fd));

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
					sizeof(struct kconsumerd_fd));
			if (local_kconsumerd_fd == NULL) {
				perror("local_kconsumerd_fd malloc");
				pthread_mutex_unlock(&kconsumerd_data.lock);
				goto end;
			}
			ret = kconsumerd_update_poll_array(&pollfd, local_kconsumerd_fd);
			if (ret < 0) {
				ERR("Error in allocating pollfd or local_outfds");
				kconsumerd_send_error(KCONSUMERD_POLL_ERROR);
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
			kconsumerd_send_error(KCONSUMERD_POLL_ERROR);
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
			tmp2 = read(kconsumerd_poll_pipe[0], &tmp, 1);
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
				ret = kconsumerd_read_subbuffer(local_kconsumerd_fd[i]);
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
					ret = kconsumerd_read_subbuffer(local_kconsumerd_fd[i]);
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
 * kconsumerd_create_poll_pipe
 *
 * create the pipe to wake to polling thread when needed
 */
int kconsumerd_create_poll_pipe()
{
	return pipe(kconsumerd_poll_pipe);
}

/*
 *  kconsumerd_thread_receive_fds
 *
 *  This thread listens on the consumerd socket and
 *  receives the file descriptors from ltt-sessiond
 */
void *kconsumerd_thread_receive_fds(void *data)
{
	int sock, client_socket, ret;
	struct lttcomm_kconsumerd_header tmp;

	DBG("Creating command socket %s", kconsumerd_command_sock_path);
	unlink(kconsumerd_command_sock_path);
	client_socket = lttcomm_create_unix_sock(kconsumerd_command_sock_path);
	if (client_socket < 0) {
		ERR("Cannot create command socket");
		goto end;
	}

	ret = lttcomm_listen_unix_sock(client_socket);
	if (ret < 0) {
		goto end;
	}

	DBG("Sending ready command to ltt-sessiond");
	ret = kconsumerd_send_error(KCONSUMERD_COMMAND_SOCK_READY);
	if (ret < 0) {
		ERR("Error sending ready command to ltt-sessiond");
		goto end;
	}

	/* TODO: poll on socket and "should_quit" fd pipe */
	/* TODO: change blocking call into non-blocking call */
	/* Blocking call, waiting for transmission */
	sock = lttcomm_accept_unix_sock(client_socket);
	if (sock <= 0) {
		WARN("On accept");
		goto end;
	}
	while (1) {
		/* We first get the number of fd we are about to receive */
		/* TODO: poll on sock and "should_quit" fd pipe */
		/* TODO: change recv into a non-blocking call */
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
		ret = kconsumerd_consumerd_recv_fd(sock, tmp.payload_size, tmp.cmd_type);
		if (ret <= 0) {
			ERR("Receiving the FD, exiting");
			goto end;
		}
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
	kconsumerd_poll_timeout = KCONSUMERD_POLL_GRACE_PERIOD;

	/* wake up the polling thread */
	ret = write(kconsumerd_poll_pipe[1], "4", 1);
	if (ret < 0) {
		perror("poll pipe write");
	}
	return NULL;
}

/*
 *  kconsumerd_cleanup
 *
 *  Cleanup the daemon's socket on exit
 */
void kconsumerd_cleanup(void)
{
	struct kconsumerd_fd *iter;

	/* remove the socket file */
	unlink(kconsumerd_command_sock_path);

	/*
	 * close all outfd. Called when there are no more threads
	 * running (after joining on the threads), no need to protect
	 * list iteration with mutex.
	 */
	cds_list_for_each_entry(iter, &kconsumerd_data.fd_list.head, list) {
		kconsumerd_del_fd(iter);
	}
}

/*
 * Called from signal handler.
 */
void kconsumerd_should_exit(void)
{
	kconsumerd_quit = 1;
	/*
	 * TODO: write into a should_quit pipe to wake up the fd
	 * receiver thread.
	 */
}

/*
 * kconsumerd_send_error
 *
 * send return code to ltt-sessiond
 */
int kconsumerd_send_error(enum lttcomm_return_code cmd)
{
	if (kconsumerd_error_socket > 0) {
		return lttcomm_send_unix_sock(kconsumerd_error_socket, &cmd,
				sizeof(enum lttcomm_sessiond_command));
	}

	return 0;
}
