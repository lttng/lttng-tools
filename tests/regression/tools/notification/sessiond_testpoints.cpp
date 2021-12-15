/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/compat/getenv.hpp>
#include <common/consumer/consumer.hpp>
#include <common/pipe.hpp>
#include <common/error.hpp>
#include <unistd.h>
#include <stdbool.h>
#include <lttng/constant.h>
#include <lttng/lttng-export.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdio.h>

static char *pause_pipe_path;
static struct lttng_pipe *pause_pipe;
static int *notifier_notif_consumption_state;;

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
			PERROR("Failed to unlink pause pipe: path = %s",
					pause_pipe_path);
		}
	}

	free(pause_pipe_path);
	lttng_pipe_destroy(pause_pipe);
}

extern "C" LTTNG_EXPORT int __testpoint_sessiond_thread_notification(void);
int __testpoint_sessiond_thread_notification(void)
{
	int ret = 0;
	const char *pause_pipe_path_prefix;

	pause_pipe_path_prefix = lttng_secure_getenv(
			"NOTIFIER_PAUSE_PIPE_PATH");
	if (!pause_pipe_path_prefix) {
		ret = -1;
		goto end;
	}

	notifier_notif_consumption_state = (int *) dlsym(NULL, "notifier_consumption_paused");
	LTTNG_ASSERT(notifier_notif_consumption_state);

	ret = asprintf(&pause_pipe_path, "%s", pause_pipe_path_prefix);
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

extern "C" LTTNG_EXPORT int __testpoint_sessiond_handle_notifier_event_pipe(void);
int __testpoint_sessiond_handle_notifier_event_pipe(void)
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
		*notifier_notif_consumption_state = !!value;
		DBG("Message received on pause pipe: %s data consumption",
				*notifier_notif_consumption_state ? "paused" : "resumed");
	}
end:
	return ret;
}
