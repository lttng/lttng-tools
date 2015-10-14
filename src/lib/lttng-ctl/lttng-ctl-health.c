/*
 * lttng-ctl-health.c
 *
 * Linux Trace Toolkit Health Control Library
 *
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _LGPL_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <lttng/health-internal.h>

#include <bin/lttng-sessiond/health-sessiond.h>
#include <bin/lttng-consumerd/health-consumerd.h>
#include <bin/lttng-relayd/health-relayd.h>
#include <common/defaults.h>
#include <common/utils.h>

#include "lttng-ctl-helper.h"

enum health_component {
	HEALTH_COMPONENT_SESSIOND,
	HEALTH_COMPONENT_CONSUMERD,
	HEALTH_COMPONENT_RELAYD,

	NR_HEALTH_COMPONENT,
};

struct lttng_health_thread {
	struct lttng_health *p;
	int state;
};

struct lttng_health {
	enum health_component component;
	uint64_t state;
	unsigned int nr_threads;
	char health_sock_path[PATH_MAX];
	/* For consumer health only */
	enum lttng_health_consumerd consumerd_type;
	struct lttng_health_thread thread[];
};

static
const char *sessiond_thread_name[NR_HEALTH_SESSIOND_TYPES] = {
	[ HEALTH_SESSIOND_TYPE_CMD ] = "Session daemon command",
	[ HEALTH_SESSIOND_TYPE_APP_MANAGE ] = "Session daemon application manager",
	[ HEALTH_SESSIOND_TYPE_APP_REG ] = "Session daemon application registration",
	[ HEALTH_SESSIOND_TYPE_KERNEL ] = "Session daemon kernel",
	[ HEALTH_SESSIOND_TYPE_CONSUMER ] = "Session daemon consumer manager",
	[ HEALTH_SESSIOND_TYPE_HT_CLEANUP ] = "Session daemon hash table cleanup",
	[ HEALTH_SESSIOND_TYPE_APP_MANAGE_NOTIFY ] = "Session daemon application notification manager",
	[ HEALTH_SESSIOND_TYPE_APP_REG_DISPATCH ] = "Session daemon application registration dispatcher",
};

static
const char *consumerd_thread_name[NR_HEALTH_CONSUMERD_TYPES] = {
	[ HEALTH_CONSUMERD_TYPE_CHANNEL ] = "Consumer daemon channel",
	[ HEALTH_CONSUMERD_TYPE_METADATA ] = "Consumer daemon metadata",
	[ HEALTH_CONSUMERD_TYPE_DATA ] = "Consumer daemon data",
	[ HEALTH_CONSUMERD_TYPE_SESSIOND ] = "Consumer daemon session daemon command manager",
	[ HEALTH_CONSUMERD_TYPE_METADATA_TIMER ] = "Consumer daemon metadata timer",
};

static
const char *relayd_thread_name[NR_HEALTH_RELAYD_TYPES] = {
	[ HEALTH_RELAYD_TYPE_DISPATCHER ] = "Relay daemon dispatcher",
	[ HEALTH_RELAYD_TYPE_WORKER ] = "Relay daemon worker",
	[ HEALTH_RELAYD_TYPE_LISTENER ] = "Relay daemon listener",
	[ HEALTH_RELAYD_TYPE_LIVE_DISPATCHER ] = "Relay daemon live dispatcher",
	[ HEALTH_RELAYD_TYPE_LIVE_WORKER ] = "Relay daemon live worker",
	[ HEALTH_RELAYD_TYPE_LIVE_LISTENER ] = "Relay daemon live listener",
};

static
const char **thread_name[NR_HEALTH_COMPONENT] = {
	[ HEALTH_COMPONENT_SESSIOND ] = sessiond_thread_name,
	[ HEALTH_COMPONENT_CONSUMERD] = consumerd_thread_name,
	[ HEALTH_COMPONENT_RELAYD ] = relayd_thread_name,
};

/*
 * Set health socket path.
 *
 * Returns 0 on success or -ENOMEM.
 */
static
int set_health_socket_path(struct lttng_health *lh,
		int tracing_group)
{
	uid_t uid;
	const char *home;
	int ret;
	/* Global and home format strings */
	const char *global_str, *home_str;

	switch (lh->component) {
	case HEALTH_COMPONENT_SESSIOND:
		global_str = DEFAULT_GLOBAL_HEALTH_UNIX_SOCK;
		home_str = DEFAULT_HOME_HEALTH_UNIX_SOCK;
		break;
	case HEALTH_COMPONENT_CONSUMERD:
		switch (lh->consumerd_type) {
		case LTTNG_HEALTH_CONSUMERD_UST_32:
			global_str = DEFAULT_GLOBAL_USTCONSUMER32_HEALTH_UNIX_SOCK;
			home_str = DEFAULT_HOME_USTCONSUMER32_HEALTH_UNIX_SOCK;
			break;
		case LTTNG_HEALTH_CONSUMERD_UST_64:
			global_str = DEFAULT_GLOBAL_USTCONSUMER64_HEALTH_UNIX_SOCK;
			home_str = DEFAULT_HOME_USTCONSUMER64_HEALTH_UNIX_SOCK;
			break;
		case LTTNG_HEALTH_CONSUMERD_KERNEL:
			global_str = DEFAULT_GLOBAL_KCONSUMER_HEALTH_UNIX_SOCK;
			home_str = DEFAULT_HOME_KCONSUMER_HEALTH_UNIX_SOCK;
			break;
		default:
			return -EINVAL;
		}
		break;
	case HEALTH_COMPONENT_RELAYD:
		if (lh->health_sock_path[0] == '\0') {
			return -EINVAL;
		} else {
			return 0;
		}
		break;	/* Unreached */
	default:
		return -EINVAL;
	}

	uid = getuid();

	if (uid == 0 || tracing_group) {
		lttng_ctl_copy_string(lh->health_sock_path,
				global_str,
				sizeof(lh->health_sock_path));
		return 0;
	}

	/*
	 * With GNU C <  2.1, snprintf returns -1 if the target buffer
	 * is too small; With GNU C >= 2.1, snprintf returns the
	 * required size (excluding closing null).
	 */
	home = utils_get_home_dir();
	if (home == NULL) {
		/* Fallback in /tmp */
		home = "/tmp";
	}

	ret = snprintf(lh->health_sock_path, sizeof(lh->health_sock_path),
			home_str, home);
	if ((ret < 0) || (ret >= sizeof(lh->health_sock_path))) {
		return -ENOMEM;
	}

	return 0;
}

static
struct lttng_health *lttng_health_create(enum health_component hc,
		unsigned int nr_threads)
{
	struct lttng_health *lh;
	int i;

	lh = zmalloc(sizeof(*lh) + sizeof(lh->thread[0]) * nr_threads);
	if (!lh) {
		return NULL;
	}

	lh->component = hc;
	lh->state = UINT64_MAX;		/* All bits in error initially */
	lh->nr_threads = nr_threads;
	for (i = 0; i < nr_threads; i++) {
		lh->thread[i].p = lh;
	}
	return lh;
}

struct lttng_health *lttng_health_create_sessiond(void)
{
	struct lttng_health *lh;

	lh = lttng_health_create(HEALTH_COMPONENT_SESSIOND,
			NR_HEALTH_SESSIOND_TYPES);
	if (!lh) {
		return NULL;
	}
	return lh;
}

struct lttng_health *
	lttng_health_create_consumerd(enum lttng_health_consumerd consumerd)
{
	struct lttng_health *lh;

	lh = lttng_health_create(HEALTH_COMPONENT_CONSUMERD,
			NR_HEALTH_CONSUMERD_TYPES);
	if (!lh) {
		return NULL;
	}
	lh->consumerd_type = consumerd;
	return lh;
}

struct lttng_health *lttng_health_create_relayd(const char *path)
{
	struct lttng_health *lh;

	if (!path) {
		return NULL;
	}

	lh = lttng_health_create(HEALTH_COMPONENT_RELAYD,
			NR_HEALTH_RELAYD_TYPES);
	if (!lh) {
		return NULL;
	}
	lttng_ctl_copy_string(lh->health_sock_path, path,
		sizeof(lh->health_sock_path));
	return lh;
}

void lttng_health_destroy(struct lttng_health *lh)
{
	free(lh);
}

int lttng_health_query(struct lttng_health *health)
{
	int sock, ret, i, tracing_group;
	struct health_comm_msg msg;
	struct health_comm_reply reply;

	if (!health) {
		return -EINVAL;
	}

	tracing_group = lttng_check_tracing_group();
retry:
	ret = set_health_socket_path(health, tracing_group);
	if (ret) {
		goto error;
	}
	/* Connect to component */
	sock = lttcomm_connect_unix_sock(health->health_sock_path);
	if (sock < 0) {
		if (tracing_group) {
			/* For tracing group, fallback to per-user */
			tracing_group = 0;
			goto retry;
		}
		ret = -1;
		goto error;
	}

	memset(&msg, 0, sizeof(msg));
	msg.cmd = HEALTH_CMD_CHECK;

	ret = lttcomm_send_unix_sock(sock, (void *)&msg, sizeof(msg));
	if (ret < 0) {
		ret = -1;
		goto close_error;
	}

	ret = lttcomm_recv_unix_sock(sock, (void *)&reply, sizeof(reply));
	if (ret < 0) {
		ret = -1;
		goto close_error;
	}

	health->state = reply.ret_code;
	for (i = 0; i < health->nr_threads; i++) {
		if (health->state & (1ULL << i)) {
			health->thread[i].state = -1;
		} else {
			health->thread[i].state = 0;
		}
	}

close_error:
	{
		int closeret;

		closeret = close(sock);
		assert(!closeret);
	}

error:
	if (ret >= 0)
		ret = 0;
	return ret;
}

int lttng_health_state(const struct lttng_health *health)
{
	if (!health) {
		return -EINVAL;
	}

	if (health->state == 0) {
		return 0;
	} else {
		return -1;
	}
}

int lttng_health_get_nr_threads(const struct lttng_health *health)
{
	if (!health) {
		return -EINVAL;
	}
	return health->nr_threads;
}

const struct lttng_health_thread *
	lttng_health_get_thread(const struct lttng_health *health,
		unsigned int nth_thread)
{
	if (!health || nth_thread >= health->nr_threads) {
		return NULL;
	}
	return &health->thread[nth_thread];
}

int lttng_health_thread_state(const struct lttng_health_thread *thread)
{
	if (!thread) {
		return -EINVAL;
	}
	return thread->state;
}

const char *lttng_health_thread_name(const struct lttng_health_thread *thread)
{
	unsigned int nr;

	if (!thread) {
		return NULL;
	}
	nr = thread - &thread->p->thread[0];
	return thread_name[thread->p->component][nr];
}
