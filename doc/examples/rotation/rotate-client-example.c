/*
 * Session rotation example control application
 *
 * Copyright 2017, Julien Desfossez <jdesfossez@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * Compile with:
 *     gcc -o rotate-client rotate-client-example.c -llttng-ctl
 *
 * Run with the following command to rotate the session every second and
 * compress the chunk, until ctrl-c:
 *     ./rotate-client mysession 1 -1 ./rotate-client-compress.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <lttng/lttng.h>

#define DEFAULT_DATA_AVAILABILITY_WAIT_TIME 200000  /* usec */

/* Uncomment to enable debug output. */
//#define DEBUG
#ifndef DEBUG
#define printf(fmt, ...) (0)
#endif

static volatile int quit = 0;

static
void sighandler(int signal)
{
	printf("Signal caught, exiting\n");
	quit = 1;
}

static
int setup_session(const char *session_name, const char *path)
{
	int ret;
	struct lttng_domain dom;
	struct lttng_event ev;
	struct lttng_handle *chan_handle;

	printf("Creating session %s\n", session_name);
	ret = lttng_create_session(session_name, path);
	if (ret) {
		fprintf(stderr, "Failed to create session, ret = %d\n", ret);
		goto end;
	}

	dom.type = LTTNG_DOMAIN_KERNEL;
	dom.buf_type = LTTNG_BUFFER_GLOBAL;

	chan_handle = lttng_create_handle(session_name, &dom);
	if (chan_handle == NULL) {
		ret = -1;
		goto end;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = LTTNG_EVENT_SYSCALL;
	strcpy(ev.name, "*");
	ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	ret = lttng_enable_event_with_exclusions(chan_handle, &ev, "mychan", NULL,
			0, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to enable events\n");
		goto end;
	}
	printf("Enabled all system call kernel events\n");

	ret = lttng_start_tracing(session_name);
	if (ret < 0) {
		fprintf(stderr, "Failed to start tracing\n");
		goto end;
	}

	lttng_destroy_handle(chan_handle);

	ret = 0;

end:
	return ret;
}

static
int cleanup_session(const char *session_name)
{
	int ret;

	printf("Stopping session %s", session_name);
	ret = lttng_stop_tracing_no_wait(session_name);
	if (ret) {
		fprintf(stderr, "Failed to stop tracing\n");
		goto end;
	}

	fflush(stdout);
	do {
		ret = lttng_data_pending(session_name);
		if (ret < 0) {
			/* Return the data available call error. */
			goto end;
		}

		/*
		 * Data sleep time before retrying (in usec). Don't sleep if the call
		 * returned value indicates availability.
		 */
		if (ret) {
			usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME);
			printf(".");
			fflush(stdout);
		}
	} while (ret != 0);
	printf("\n");

	printf("Destroying session %s\n", session_name);
	ret = lttng_destroy_session(session_name);
	if (ret) {
		fprintf(stderr, "Failed to destroy the session\n");
		goto end;
	}

	ret = 0;

end:
	return ret;
}

static
int rotate_session(const char *session_name, const char *ext_program)
{
	int ret;
	char *path = NULL;
	struct lttng_rotation_manual_attr *attr = NULL;
	struct lttng_rotation_handle *handle = NULL;
	enum lttng_rotation_status rotation_status;
	char cmd[PATH_MAX];

	attr = lttng_rotation_manual_attr_create();
	if (!attr) {
		fprintf(stderr, "Failed to create rotate attr\n");
		ret = -1;
		goto end;
	}

	ret = lttng_rotation_manual_attr_set_session_name(attr, session_name);
	if (ret < 0) {
		fprintf(stderr, "Failed to set rotate attr session name\n");
		goto end;
	}

	printf("Rotating the output files of session %s", session_name);

	ret = lttng_rotate_session(attr, &handle);
	if (ret < 0) {
		fprintf(stderr, "Failed to rotate session, %s\n", lttng_strerror(ret));
		goto end;
	}

	fflush(stdout);
	do {
		ret = lttng_rotation_is_pending(handle);
		if (ret < 0) {
			fprintf(stderr, "Rotate pending failed\n");
			goto end;
		}

		/*
		 * Data sleep time before retrying (in usec). Don't sleep if the call
		 * returned value indicates availability.
		 */
		if (ret) {
			usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME);
			printf(".");
			fflush(stdout);
		}
	} while (ret == 1);
	printf("\n");

	rotation_status = lttng_rotation_handle_get_status(handle);
	switch(rotation_status) {
	case LTTNG_ROTATION_STATUS_COMPLETED:
		lttng_rotation_handle_get_output_path(handle, &path);
		printf("Output files of session %s rotated to %s\n", session_name, path);
		ret = snprintf(cmd, PATH_MAX, "%s %s", ext_program, path);
		if (ret < 0) {
			fprintf(stderr, "Failed to prepare command string\n");
			goto end;
		}
		ret = system(cmd);
		goto end;
	case LTTNG_ROTATION_STATUS_STARTED:
		/* Should not happen after a rotate_pending. */
		printf("Rotation started for session %s\n", session_name);
		ret = 0;
		goto end;
	case LTTNG_ROTATION_STATUS_EXPIRED:
		printf("Output files of session %s rotated, but handle expired", session_name);
		ret = 0;
		goto end;
	case LTTNG_ROTATION_STATUS_ERROR:
		fprintf(stderr, "An error occurred with the rotation of session %s", session_name);
		ret = -1;
		goto end;
	}

end:
	lttng_rotation_handle_destroy(handle);
	lttng_rotation_manual_attr_destroy(attr);
	return ret;
}

static
int cleanup_dir(const char *path)
{
	char cmd[PATH_MAX];
	int ret;

	ret = snprintf(cmd, PATH_MAX, "rm -rf %s", path);
	if (ret < 0) {
		fprintf(stderr, "Failed to prepare rm -rf command string\n");
		goto end;
	}
	ret = system(cmd);

end:
	return ret;
}

void usage(const char *prog_name)
{
	fprintf(stderr, "Usage: %s <session-name> <delay-sec> <nr-rotate> <program>\n",
			prog_name);
	fprintf(stderr, "  <session-name>: the name of the session you want to create\n");
	fprintf(stderr, "  <delay-sec>: the delay in seconds between each rotation\n");
	fprintf(stderr, "  <nr-rotate>: the number of rotation you want to perform, "
			"-1 for infinite until ctrl-c\n");
	fprintf(stderr, "  <program>: program to run on each chunk, it must be "
			"executable, and expect a trace folder as only argument\n");
	fprintf(stderr, "\nThe trace folder is deleted when this program completes.\n");
}

int main(int argc, char **argv)
{
	int ret;
	char tmppath[] = "/tmp/lttng-rotate-XXXXXX";
	char *session_name, *path, *ext_program;
	int delay, nr;

	if (argc != 5) {
		usage(argv[0]);
		ret = -1;
		goto end;
	}

	session_name = argv[1];
	delay = atoi(argv[2]);
	nr = atoi(argv[3]);
	ext_program = argv[4];

	if (delay < 0) {
		fprintf(stderr, "delay-sec must be a positive values\n");
		ret = -1;
		goto end;
	}

	if  (signal(SIGINT, sighandler) == SIG_ERR) {
		perror("signal handler");
		goto end;
	}

	path = mkdtemp(tmppath);
	if (!path) {
		fprintf(stderr, "Failed to create temporary path\n");
	}

	printf("Output directory: %s\n", path);

	ret = setup_session(session_name, path);
	if (ret) {
		goto end_cleanup_dir;
	}

	if (nr > 0) {
		unsigned int sleep_time;
		int i;

		for (i = 0; i < nr; i++) {
			ret = rotate_session(session_name, ext_program);
			if (ret) {
				goto end_cleanup;
			}
			sleep_time = delay;
			while (sleep_time > 0) {
				sleep_time = sleep(sleep_time);
			}
		}
	} else {
		for(;;) {
			if (quit) {
				break;
			}
			ret = rotate_session(session_name, ext_program);
			if (ret) {
				goto end_cleanup;
			}
			sleep(delay);
		}
	}

end_cleanup:
	ret = cleanup_session(session_name);
	if (ret) {
		goto end;
	}
end_cleanup_dir:
	ret = cleanup_dir(path);
end:
	return ret;
}
