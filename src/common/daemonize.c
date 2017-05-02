/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2014 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <unistd.h>
#include <common/compat/paths.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>

#include <urcu/system.h>

#include <common/daemonize.h>
#include <common/error.h>

LTTNG_HIDDEN
int lttng_daemonize(pid_t *child_ppid, int *completion_flag,
		int close_fds)
{
	int ret;
	pid_t pid;

	/* Get parent pid of this process. */
	*child_ppid = getppid();

	pid = fork();
	if (pid < 0) {
		PERROR("fork");
		goto error;
	} else if (pid == 0) {
		int fd;
		pid_t sid;

		/* Child */

		/*
		 * Get the newly created parent pid so we can signal
		 * that process when we are ready to operate.
		 */
		*child_ppid = getppid();

		sid = setsid();
		if (sid < 0) {
			PERROR("setsid");
			goto error;
		}

		/*
		 * Try to change directory to /. If we can't well at
		 * least notify.
		 */
		ret = chdir("/");
		if (ret < 0) {
			PERROR("chdir");
		}

		if (close_fds) {
			fd = open(_PATH_DEVNULL, O_RDWR, 0);
			if (fd < 0) {
				PERROR("open %s", _PATH_DEVNULL);
				/*
				 * Let 0, 1 and 2 open since we can't
				 * bind them to /dev/null.
				 */
			} else {
				(void) dup2(fd, STDIN_FILENO);
				(void) dup2(fd, STDOUT_FILENO);
				(void) dup2(fd, STDERR_FILENO);
				if (fd > 2) {
					ret = close(fd);
					if (ret < 0) {
						PERROR("close");
					}
				}
			}
		}
		goto end;
	} else {
		/* Parent */

		/*
		 * Waiting for child to notify this parent that it can
		 * exit. Note that sleep() is interrupted before the 1
		 * second delay as soon as the signal is received, so it
		 * will not cause visible delay for the user.
		 */
		while (!CMM_LOAD_SHARED(*completion_flag)) {
			int status;
			pid_t ret;

			/*
			 * Check if child exists without blocking. If
			 * so, we have to stop this parent process and
			 * return an error.
			 */
			ret = waitpid(pid, &status, WNOHANG);
			if (ret < 0 || (ret != 0 && WIFEXITED(status))) {
				/* The child exited somehow or was not valid. */
				goto error;
			}
			sleep(1);
		}

		/*
		 * From this point on, the parent can exit and the child
		 * is now an operationnal session daemon ready to serve
		 * clients and applications.
		 */
		exit(EXIT_SUCCESS);
	}

end:
	return 0;

error:
	return -1;
}
