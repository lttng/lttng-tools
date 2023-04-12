/*
 * lttng-ctl-health.c
 *
 * Linux Trace Toolkit Health Control Library
 *
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "lttng-ctl-helper.hpp"

#include <common/compat/errno.hpp>
#include <common/compiler.hpp>
#include <common/defaults.hpp>
#include <common/utils.hpp>

#include <lttng/health-internal.hpp>

#include <bin/lttng-consumerd/health-consumerd.hpp>
#include <bin/lttng-relayd/health-relayd.hpp>
#include <bin/lttng-sessiond/health-sessiond.hpp>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

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
	struct lttng_health_thread thread[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
};

static const char *get_sessiond_thread_name(health_type_sessiond type)
{
	switch (type) {
	case HEALTH_SESSIOND_TYPE_CMD:
		return "Session daemon command";
	case HEALTH_SESSIOND_TYPE_APP_MANAGE:
		return "Session daemon application manager";
	case HEALTH_SESSIOND_TYPE_APP_REG:
		return "Session daemon application registration";
	case HEALTH_SESSIOND_TYPE_KERNEL:
		return "Session daemon kernel";
	case HEALTH_SESSIOND_TYPE_CONSUMER:
		return "Session daemon consumer manager";
	case HEALTH_SESSIOND_TYPE_APP_MANAGE_NOTIFY:
		return "Session daemon application notification manager";
	case HEALTH_SESSIOND_TYPE_APP_REG_DISPATCH:
		return "Session daemon application registration dispatcher";
	case HEALTH_SESSIOND_TYPE_NOTIFICATION:
		return "Session daemon notification";
	case HEALTH_SESSIOND_TYPE_ROTATION:
		return "Session daemon rotation manager";
	case HEALTH_SESSIOND_TYPE_TIMER:
		return "Session daemon timer manager";
	case HEALTH_SESSIOND_TYPE_ACTION_EXECUTOR:
		return "Session daemon trigger action executor";
	case NR_HEALTH_SESSIOND_TYPES:
		abort();
	}

	abort();
};

static const char *get_consumerd_thread_name(health_type_consumerd type)
{
	switch (type) {
	case HEALTH_CONSUMERD_TYPE_CHANNEL:
		return "Consumer daemon channel";
	case HEALTH_CONSUMERD_TYPE_METADATA:
		return "Consumer daemon metadata";
	case HEALTH_CONSUMERD_TYPE_DATA:
		return "Consumer daemon data";
	case HEALTH_CONSUMERD_TYPE_SESSIOND:
		return "Consumer daemon session daemon command manager";
	case HEALTH_CONSUMERD_TYPE_METADATA_TIMER:
		return "Consumer daemon metadata timer";
	case NR_HEALTH_CONSUMERD_TYPES:
		abort();
	}

	abort();
};

static const char *get_relayd_thread_name(health_type_relayd type)
{
	switch (type) {
	case HEALTH_RELAYD_TYPE_DISPATCHER:
		return "Relay daemon dispatcher";
	case HEALTH_RELAYD_TYPE_WORKER:
		return "Relay daemon worker";
	case HEALTH_RELAYD_TYPE_LISTENER:
		return "Relay daemon listener";
	case HEALTH_RELAYD_TYPE_LIVE_DISPATCHER:
		return "Relay daemon live dispatcher";
	case HEALTH_RELAYD_TYPE_LIVE_WORKER:
		return "Relay daemon live worker";
	case HEALTH_RELAYD_TYPE_LIVE_LISTENER:
		return "Relay daemon live listener";
	case NR_HEALTH_RELAYD_TYPES:
		abort();
	}

	abort();
}

static const char *get_thread_name(int comp, int nr)
{
	switch (comp) {
	case HEALTH_COMPONENT_SESSIOND:
		return get_sessiond_thread_name((health_type_sessiond) nr);
	case HEALTH_COMPONENT_CONSUMERD:
		return get_consumerd_thread_name((health_type_consumerd) nr);
	case HEALTH_COMPONENT_RELAYD:
		return get_relayd_thread_name((health_type_relayd) nr);
	case NR_HEALTH_COMPONENT:
		abort();
	}

	abort();
}

/*
 * Set health socket path.
 *
 * Returns 0 on success or a negative errno.
 */
static int set_health_socket_path(struct lttng_health *lh, int tracing_group)
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
		break; /* Unreached */
	default:
		return -EINVAL;
	}

	uid = getuid();

	if (uid == 0 || tracing_group) {
		ret = lttng_strncpy(lh->health_sock_path, global_str, sizeof(lh->health_sock_path));
		return ret == 0 ? 0 : -EINVAL;
	}

	/*
	 * With GNU C <  2.1, snprintf returns -1 if the target buffer
	 * is too small; With GNU C >= 2.1, snprintf returns the
	 * required size (excluding closing null).
	 */
	home = utils_get_home_dir();
	if (home == nullptr) {
		/* Fallback in /tmp */
		home = "/tmp";
	}

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_FORMAT_NONLITERAL
	ret = snprintf(lh->health_sock_path, sizeof(lh->health_sock_path), home_str, home);
	DIAGNOSTIC_POP
	if ((ret < 0) || (ret >= sizeof(lh->health_sock_path))) {
		return -ENOMEM;
	}

	return 0;
}

static struct lttng_health *lttng_health_create(enum health_component hc, unsigned int nr_threads)
{
	struct lttng_health *lh;
	int i;

	lh = zmalloc<lttng_health>(sizeof(*lh) + sizeof(lh->thread[0]) * nr_threads);
	if (!lh) {
		return nullptr;
	}

	lh->component = hc;
	lh->state = UINT64_MAX; /* All bits in error initially */
	lh->nr_threads = nr_threads;
	for (i = 0; i < nr_threads; i++) {
		lh->thread[i].p = lh;
	}
	return lh;
}

struct lttng_health *lttng_health_create_sessiond(void)
{
	struct lttng_health *lh;

	lh = lttng_health_create(HEALTH_COMPONENT_SESSIOND, NR_HEALTH_SESSIOND_TYPES);
	if (!lh) {
		return nullptr;
	}
	return lh;
}

struct lttng_health *lttng_health_create_consumerd(enum lttng_health_consumerd consumerd)
{
	struct lttng_health *lh;

	lh = lttng_health_create(HEALTH_COMPONENT_CONSUMERD, NR_HEALTH_CONSUMERD_TYPES);
	if (!lh) {
		return nullptr;
	}
	lh->consumerd_type = consumerd;
	return lh;
}

struct lttng_health *lttng_health_create_relayd(const char *path)
{
	int ret;
	struct lttng_health *lh = nullptr;

	if (!path) {
		goto error;
	}

	lh = lttng_health_create(HEALTH_COMPONENT_RELAYD, NR_HEALTH_RELAYD_TYPES);
	if (!lh) {
		goto error;
	}

	ret = lttng_strncpy(lh->health_sock_path, path, sizeof(lh->health_sock_path));
	if (ret) {
		goto error;
	}

	return lh;

error:
	free(lh);
	return nullptr;
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

	ret = lttcomm_send_unix_sock(sock, (void *) &msg, sizeof(msg));
	if (ret < 0) {
		ret = -1;
		goto close_error;
	}

	ret = lttcomm_recv_unix_sock(sock, (void *) &reply, sizeof(reply));
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
	LTTNG_ASSERT(!closeret);
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

const struct lttng_health_thread *lttng_health_get_thread(const struct lttng_health *health,
							  unsigned int nth_thread)
{
	if (!health || nth_thread >= health->nr_threads) {
		return nullptr;
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
		return nullptr;
	}
	nr = thread - &thread->p->thread[0];
	return get_thread_name(thread->p->component, nr);
}
