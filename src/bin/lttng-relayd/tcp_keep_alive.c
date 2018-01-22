/*
 * Copyright (C) 2017 - Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <limits.h>

#include <common/compat/getenv.h>
#include <common/time.h>
#include <common/defaults.h>
#include <common/config/session-config.h>

#include "tcp_keep_alive.h"

#define SOLARIS_IDLE_TIME_MIN_S 10
#define SOLARIS_IDLE_TIME_MAX_S 864000 /* 10 days */
#define SOLARIS_ABORT_THRESHOLD_MIN_S 1
#define SOLARIS_ABORT_THRESHOLD_MAX_S 480 /* 8 minutes */

/* Per-platform definitions of TCP socket options. */
#if defined (__linux__)

#define COMPAT_SOCKET_LEVEL SOL_TCP
#define COMPAT_TCP_LEVEL SOL_TCP
#define COMPAT_TCP_ABORT_THRESHOLD 0 /* Does not exist on linux. */
#define COMPAT_TCP_KEEPIDLE TCP_KEEPIDLE
#define COMPAT_TCP_KEEPINTVL TCP_KEEPINTVL
#define COMPAT_TCP_KEEPCNT TCP_KEEPCNT

#elif defined (__sun__) /* ! defined (__linux__) */

#define COMPAT_SOCKET_LEVEL SOL_SOCKET
#define COMPAT_TCP_LEVEL IPPROTO_TCP

#ifdef TCP_KEEPALIVE_THRESHOLD
#define COMPAT_TCP_KEEPIDLE TCP_KEEPALIVE_THRESHOLD
#else /* ! defined (TCP_KEEPALIVE_THRESHOLD) */
#define COMPAT_TCP_KEEPIDLE 0
#endif /* TCP_KEEPALIVE_THRESHOLD */

#ifdef TCP_KEEPALIVE_ABORT_THRESHOLD
#define COMPAT_TCP_ABORT_THRESHOLD TCP_KEEPALIVE_ABORT_THRESHOLD
#else /* ! defined (TCP_KEEPALIVE_ABORT_THRESHOLD) */
#define COMPAT_TCP_ABORT_THRESHOLD 0
#endif /* TCP_KEEPALIVE_ABORT_THRESHOLD */

#define COMPAT_TCP_KEEPINTVL 0 /* Does not exist on Solaris. */
#define COMPAT_TCP_KEEPCNT 0 /* Does not exist on Solaris. */

#else /* ! defined (__linux__) && ! defined (__sun__) */

#define COMPAT_SOCKET_LEVEL 0
#define COMPAT_TCP_LEVEL 0
#define COMPAT_TCP_ABORT_THRESHOLD 0
#define COMPAT_TCP_KEEPIDLE 0
#define COMPAT_TCP_KEEPINTVL 0
#define COMPAT_TCP_KEEPCNT 0

#endif /* ! defined (__linux__) && ! defined (__sun__) */

struct tcp_keep_alive_support {
	/* TCP keep-alive is supported by this platform. */
	bool supported;
	/* Overriding idle-time per socket is supported by this platform. */
	bool idle_time_supported;
	/*
	 * Overriding probe interval per socket is supported by this
	 * platform.
	 */
	bool probe_interval_supported;
	/*
	 * Configuring max probe count per socket is supported by this
	 * platform.
	 */
	bool max_probe_count_supported;
	/* Overriding on a per-socket basis is supported by this platform. */
	bool abort_threshold_supported;
};

struct tcp_keep_alive_config {
	/* Maps to the LTTNG_RELAYD_TCP_KEEP_ALIVE_ENV environment variable. */
	bool enabled;
	/*
	 * Maps to the LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV environment
	 * variable.
	 */
	int idle_time;
	/*
	 * Maps to the LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV
	 * environment variable.
	 */
	int probe_interval;
	/*
	 * Maps to the LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV
	 * environment variable.
	 */
	int max_probe_count;
	/*
	 * Maps to the LTTNG_RELAYD_TCP_KEEP_ALIVE_ABORT_THRESHOLD_ENV
	 * environment variable.
	 */
	int abort_threshold;
};

static struct tcp_keep_alive_config config = {
	.enabled = false,
	.idle_time = -1,
	.probe_interval = -1,
	.max_probe_count = -1,
	.abort_threshold = -1
};

static struct tcp_keep_alive_support support = {
	.supported = false,
	.idle_time_supported = false,
	.probe_interval_supported = false,
	.max_probe_count_supported = false,
	.abort_threshold_supported = false
};

/*
 * Common parser for string to positive int conversion where the value must be
 * in range [-1, INT_MAX].
 *
 * Returns -2 on invalid value.
 */
static
int get_env_int(const char *env_var,
		const char *value)
{
	int ret;
	long tmp;
	char *endptr = NULL;

	errno = 0;
	tmp = strtol(value, &endptr, 0);
	if (errno != 0) {
		ERR("%s cannot be parsed.", env_var);
		PERROR("errno for previous parsing failure");
		ret = -2;
		goto end;
	}

	if (endptr == value || *endptr != '\0') {
	    ERR("%s is not a valid number", env_var);
	    ret = -1;
	    goto end;
	}

	if (tmp < -1) {
		ERR("%s must be greater or equal to -1", env_var);
		ret = -2;
		goto end;
	}
	if (tmp > INT_MAX){
		ERR("%s is too big. Maximum value is %d", env_var, INT_MAX);
		ret = -2;
		goto end;
	}

	ret = (int) tmp;
end:
	return ret;
}

/*
 * Per-platform implementation of tcp_keep_alive_idle_time_modifier.
 * Returns -2 on invalid value.
 */
#ifdef __sun__

static
int convert_idle_time(int value)
{
	int ret;
	unsigned int tmp_ms;

	if (value == -1 || value == 0) {
		/* Use system defaults */
		ret = value;
		goto end;
	}

	if (value < 0) {
		ERR("Invalid tcp keep-alive idle time (%i)", value);
		ret = -2;
		goto end;
	}

	/*
	 * Additional constraints for Solaris 11.
	 * Minimum 10s, maximum 10 days. Defined by
	 * https://docs.oracle.com/cd/E23824_01/html/821-1475/tcp-7p.html#REFMAN7tcp-7p
	 */
	if ((value < SOLARIS_IDLE_TIME_MIN_S ||
			value > SOLARIS_IDLE_TIME_MAX_S)) {
		ERR("%s must be comprised between %d and %d inclusively on Solaris",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV,
				SOLARIS_IDLE_TIME_MIN_S,
				SOLARIS_IDLE_TIME_MAX_S);
		ret = -2;
		goto end;
	}

	/* On Solaris idle time is given in milliseconds. */
	tmp_ms = ((unsigned int) value) * MSEC_PER_SEC;
	if ((value != 0 && (tmp_ms / ((unsigned int) value)) != MSEC_PER_SEC)
			|| tmp_ms > INT_MAX) {
		/* Overflow. */
		const int max_value = INT_MAX / MSEC_PER_SEC;

		ERR("%s is too big: maximum supported value is %d",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV,
				max_value);
		ret = -2;
		goto end;
	}

	/* tmp_ms is >= 0 and <= INT_MAX. Cast is safe. */
	ret = (int) tmp_ms;
end:
	return ret;
}

#else /* ! defined(__sun__) */

static
int convert_idle_time(int value)
{
	return value;
}

#endif /* ! defined(__sun__) */

/* Per-platform support of tcp_keep_alive functionality. */
#if defined (__linux__)

static
void tcp_keep_alive_init_support(struct tcp_keep_alive_support *support)
{
	support->supported = true;
	support->idle_time_supported = true;
	support->probe_interval_supported = true;
	support->max_probe_count_supported = true;
	/* Solaris specific */
	support->abort_threshold_supported = false;
}

#elif defined(__sun__) /* ! defined (__linux__) */

static
void tcp_keep_alive_init_support(struct tcp_keep_alive_support *support)
{
	support->supported = true;
#ifdef TCP_KEEPALIVE_THRESHOLD
	support->idle_time_supported = true;
#else
	support->idle_time_supported = false;;
#endif /* TCP_KEEPALIVE_THRESHOLD */

	/*
	 * Solaris does not support either tcp_keepalive_probes or
	 * tcp_keepalive_intvl.
	 * Inferring a value for TCP_KEEP_ALIVE_ABORT_THRESHOLD using
	 * (tcp_keepalive_probes * tcp_keepalive_intvl) could yield a good
	 * alternative, but Solaris does not detail the algorithm used (such as
	 * constant time retry like Linux).
	 *
	 * Ignore those settings on Solaris 11. We prefer exposing an
	 * environment variable only used on Solaris for the abort threshold.
	 */
	support->probe_interval_supported = false;
	support->max_probe_count_supported = false;
#ifdef TCP_KEEPALIVE_ABORT_THRESHOLD
	support->abort_threshold_supported = true;
#else
	support->abort_threshold_supported = false;
#endif /* TCP_KEEPALIVE_THRESHOLD */
}

#else /* ! defined(__sun__) && ! defined(__linux__) */

/* Assume nothing is supported on other platforms. */
static
void tcp_keep_alive_init_support(struct tcp_keep_alive_support *support)
{
	support->supported = false;
	support->idle_time_supported = false;
	support->probe_interval_supported = false;
	support->max_probe_count_supported = false;
	support->abort_threshold_supported = false;
}

#endif /* ! defined(__sun__) && ! defined(__linux__) */

#ifdef __sun__

/*
 * Solaris specific modifier for abort threshold.
 * Return -2 on error.
 */
static
int convert_abort_threshold(int value)
{
	int ret;
	unsigned int tmp_ms;

	if (value == -1) {
		/* Use system defaults */
		ret = value;
		goto end;
	}

	if (value < 0) {
		ERR("Invalid tcp keep-alive abort threshold (%i)", value);
		ret = -2;
		goto end;
	}

	/*
	 * Additional constraints for Solaris 11.
	 *
	 * Between 0 and 8 minutes.
	 * https://docs.oracle.com/cd/E19120-01/open.solaris/819-2724/fsvdh/index.html
	 *
	 * Restrict from 1 seconds to 8 minutes sice the 0 value goes against
	 * the purpose of dead peers detection by never timing out when probing.
	 * It does NOT mean that the connection times out immediately.
	 */
	if ((value < SOLARIS_ABORT_THRESHOLD_MIN_S || value > SOLARIS_ABORT_THRESHOLD_MAX_S)) {
		ERR("%s must be comprised between %d and %d inclusively on Solaris",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ABORT_THRESHOLD_ENV,
				SOLARIS_ABORT_THRESHOLD_MIN_S,
				SOLARIS_ABORT_THRESHOLD_MAX_S);
		ret = -2;
		goto end;
	}

	/* Abort threshold is given in milliseconds. */
	tmp_ms = ((unsigned int) value) * MSEC_PER_SEC;
	if ((value != 0 && (tmp_ms / ((unsigned int) value)) != MSEC_PER_SEC)
			|| tmp_ms > INT_MAX) {
		/* Overflow */
		const int max_value = INT_MAX / MSEC_PER_SEC;

		ERR("%s is too big: maximum supported value is %d",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ABORT_THRESHOLD_ENV,
				max_value);
		ret = -2;
		goto end;
	}

	/* tmp_ms is >= 0 and <= INT_MAX. Cast is safe. */
	ret = (int) tmp_ms;
end:
	return ret;
}

#else

static
int convert_abort_threshold(int value)
{
	return value;
}

#endif /* defined (__sun__) */

/*
 * Retrieve settings from environment variables and warn for settings not
 * supported by the platform.
 */
static
int tcp_keep_alive_init_config(struct tcp_keep_alive_support *support,
		struct tcp_keep_alive_config *config)
{
	int ret;
	const char *value;

	value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ENV);
	if (!support->supported) {
		if (value) {
			WARN("Using per-socket TCP keep-alive mechanism is not supported by this platform. Ignoring the %s environment variable.",
					DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ENV);
		}
		config->enabled = false;
	} else if (value) {
		ret = config_parse_value(value);
		if (ret < 0 || ret > 1) {
			ERR("Invalid value for %s", DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ENV);
			ret = 1;
			goto error;
		}
		config->enabled = ret;
	}
	DBG("TCP keep-alive mechanism %s", config->enabled ? "enabled": "disabled");

	/* Get value for tcp_keepalive_time in seconds. */
	value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV);
	if (!support->idle_time_supported && value) {
		WARN("Overriding the TCP keep-alive idle time threshold per-socket is not supported by this platform. Ignoring the %s environment variable.",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV);
		config->idle_time = -1;
	} else if (value) {
		int idle_time_platform;
		int idle_time_seconds;

		idle_time_seconds = get_env_int(
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV,
				value);
		if (idle_time_seconds < -1) {
			ret = 1;
			goto error;
		}

		idle_time_platform = convert_idle_time(idle_time_seconds);
		if (idle_time_platform < -1) {
			ret = 1;
			goto error;
		}

		config->idle_time = idle_time_platform;
		DBG("Overriding %s to %d",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV,
				idle_time_seconds);
	}

	/* Get value for tcp_keepalive_intvl in seconds. */
	value = lttng_secure_getenv(
			DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV);
	if (!support->probe_interval_supported && value) {
		WARN("Overriding the TCP keep-alive probe interval time per-socket is not supported by this platform. Ignoring the %s environment variable.",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV);
		config->probe_interval = -1;
	} else if (value) {
		int probe_interval;

		probe_interval = get_env_int(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV,
				value);
		if (probe_interval < -1) {
			ret = 1;
			goto error;
		}

		config->probe_interval = probe_interval;
		DBG("Overriding %s to %d",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV,
				config->probe_interval);
	}

	/* Get value for tcp_keepalive_probes. */
	value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV);
	if (!support->max_probe_count_supported && value) {
		WARN("Overriding the TCP keep-alive maximum probe count per-socket is not supported by this platform. Ignoring the %s environment variable.",
				 DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV);
		config->max_probe_count = -1;
	} else if (value) {
		int max_probe_count;

		max_probe_count = get_env_int(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV,
				value);
		if (max_probe_count < -1) {
			ret = 1;
			goto error;
		}

		config->max_probe_count = max_probe_count;
		DBG("Overriding %s to %d",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV,
				config->max_probe_count);
	}

	/* Get value for tcp_keepalive_abort_interval. */
	value = lttng_secure_getenv(
			DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ABORT_THRESHOLD_ENV);
	if (!support->abort_threshold_supported && value) {
		WARN("Overriding the TCP keep-alive abort threshold per-socket is not supported by this platform. Ignoring the %s environment variable.",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ABORT_THRESHOLD_ENV);
		config->abort_threshold = -1;
	} else if (value) {
		int abort_threshold_platform;
		int abort_threshold_seconds;

		abort_threshold_seconds = get_env_int(
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV,
				value);
		if (abort_threshold_seconds < -1) {
			ret = 1;
			goto error;
		}

		abort_threshold_platform = convert_abort_threshold(
				abort_threshold_seconds);
		if (abort_threshold_platform < -1) {
			ret = 1;
			goto error;
		}

		config->abort_threshold = abort_threshold_platform;
		DBG("Overriding %s to %d",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ABORT_THRESHOLD_ENV,
				config->abort_threshold);
	}

	ret = 0;

error:
	return ret;
}

/* Initialize the TCP keep-alive configuration. */
__attribute__((constructor)) static
int tcp_keep_alive_init(void)
{
	tcp_keep_alive_init_support(&support);
	return tcp_keep_alive_init_config(&support, &config);
}

/*
 * Set the socket options regarding TCP keep-alive.
 */
LTTNG_HIDDEN
int socket_apply_keep_alive_config(int socket_fd)
{
	int ret;
	int val = 1;

	/* TCP keep-alive */
	if (!support.supported || !config.enabled ) {
		ret = 0;
		goto end;
	}

	ret = setsockopt(socket_fd, COMPAT_SOCKET_LEVEL, SO_KEEPALIVE, &val,
			sizeof(val));
	if (ret < 0) {
		PERROR("setsockopt so_keepalive");
		goto end;
	}

	/* TCP keep-alive idle time */
	if (support.idle_time_supported && config.idle_time > 0) {
		ret = setsockopt(socket_fd, COMPAT_TCP_LEVEL, COMPAT_TCP_KEEPIDLE, &config.idle_time,
				sizeof(config.idle_time));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPIDLE");
			goto end;
		}
	}
	/* TCP keep-alive probe interval */
	if (support.probe_interval_supported && config.probe_interval > 0) {
		ret = setsockopt(socket_fd, COMPAT_TCP_LEVEL, COMPAT_TCP_KEEPINTVL, &config.probe_interval,
				sizeof(config.probe_interval));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPINTVL");
			goto end;
		}
	}

	/* TCP keep-alive max probe count */
	if (support.max_probe_count_supported && config.max_probe_count > 0) {
		ret = setsockopt(socket_fd, COMPAT_TCP_LEVEL, COMPAT_TCP_KEEPCNT, &config.max_probe_count,
				sizeof(config.max_probe_count));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPCNT");
			goto end;
		}
	}

	/* TCP keep-alive abort threshold */
	if (support.abort_threshold_supported && config.abort_threshold > 0) {
		ret = setsockopt(socket_fd, COMPAT_TCP_LEVEL, COMPAT_TCP_ABORT_THRESHOLD, &config.abort_threshold,
				sizeof(config.max_probe_count));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPALIVE_ABORT_THRESHOLD");
			goto end;
		}
	}
end:
	return ret;
}
