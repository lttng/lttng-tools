/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <common/compat/getenv.h>
#include <common/consumer/consumer.h>
#include <common/pipe.h>
#include <common/error.h>
#include <unistd.h>
#include <stdbool.h>
#include <lttng/constant.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <assert.h>
#include <stdio.h>

static char *pause_pipe_path;
static struct lttng_pipe *pause_pipe;
static int *data_consumption_state;
static enum lttng_consumer_type (*lttng_consumer_get_type)(void);

int lttng_opt_verbose;
int lttng_opt_mi;
int lttng_opt_quiet;

static
void __attribute__((destructor)) pause_pipe_fini(void)
{
	int ret;

	if (pause_pipe_path) {
		ret = unlink(pause_pipe_path);
		if (ret) {
			PERROR("unlink pause pipe");
		}
	}

	free(pause_pipe_path);
	lttng_pipe_destroy(pause_pipe);
}

/*
 * We use this testpoint, invoked at the start of the consumerd's data handling
 * thread to create a named pipe/FIFO which a test application can use to either
 * pause or resume the consumption of data.
 */
int __testpoint_consumerd_thread_data(void)
{
	int ret = 0;
	const char *pause_pipe_path_prefix, *domain;

	pause_pipe_path_prefix = lttng_secure_getenv(
			"CONSUMER_PAUSE_PIPE_PATH");
	if (!pause_pipe_path_prefix) {
		ret = -1;
		goto end;
	}

	/*
	 * These symbols are exclusive to the consumerd process, hence we can't
	 * rely on their presence in the sessiond. Not looking-up these symbols
	 * dynamically would not allow this shared object to be LD_PRELOAD-ed
	 * when launching the session daemon.
	 */
	data_consumption_state = dlsym(NULL, "data_consumption_paused");
	assert(data_consumption_state);
	lttng_consumer_get_type = dlsym(NULL, "lttng_consumer_get_type");
	assert(lttng_consumer_get_type);

	switch (lttng_consumer_get_type()) {
	case LTTNG_CONSUMER_KERNEL:
		domain = "kernel";
		break;
	case LTTNG_CONSUMER32_UST:
		domain = "ust32";
		break;
	case LTTNG_CONSUMER64_UST:
		domain = "ust64";
		break;
	default:
		abort();
	}

	ret = asprintf(&pause_pipe_path, "%s-%s", pause_pipe_path_prefix,
			domain);
	if (ret < 1) {
		ERR("Failed to allocate pause pipe path");
		goto end;
	}

	DBG("Creating pause pipe at %s", pause_pipe_path);
	pause_pipe = lttng_pipe_named_open(pause_pipe_path,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP, O_NONBLOCK);
	if (!pause_pipe) {
		ERR("Failed to create pause pipe at %s", pause_pipe_path);
		ret = -1;
		goto end;
	}

	/* Only the read end of the pipe is useful to us. */
	ret = lttng_pipe_write_close(pause_pipe);
end:
	return ret;
}

int __testpoint_consumerd_thread_data_poll(void)
{
	int ret = 0;
	uint8_t value;
	bool value_read = false;

	if (!pause_pipe) {
		ret = -1;
		goto end;
	}

	/* Purge pipe and only consider the freshest value. */
	do {
		ret = lttng_pipe_read(pause_pipe, &value, sizeof(value));
		if (ret == sizeof(value)) {
			value_read = true;
		}
	} while (ret == sizeof(value));

	ret = (errno == EAGAIN) ? 0 : -errno;

	if (value_read) {
		*data_consumption_state = !!value;
		DBG("Message received on pause pipe: %s data consumption",
				*data_consumption_state ? "paused" : "resumed");
	}
end:
	return ret;
}
