/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>

#include <common/error.h>
#include <common/utils.h>
#include <common/defaults.h>

#include "conf.h"
#include "utils.h"
#include "command.h"

static const char *str_kernel = "Kernel";
static const char *str_ust = "UST";
static const char *str_jul = "JUL";
static const char *str_log4j = "LOG4J";
static const char *str_python = "Python";

static
char *_get_session_name(int quiet)
{
	char *path, *session_name = NULL;

	/* Get path to config file */
	path = utils_get_home_dir();
	if (path == NULL) {
		goto error;
	}

	/* Get session name from config */
	session_name = quiet ? config_read_session_name_quiet(path) :
		config_read_session_name(path);
	if (session_name == NULL) {
		goto error;
	}

	DBG2("Config file path found: %s", path);
	DBG("Session name found: %s", session_name);
	return session_name;

error:
	return NULL;
}

/*
 *  get_session_name
 *
 *  Return allocated string with the session name found in the config
 *  directory.
 */
char *get_session_name(void)
{
	return _get_session_name(0);
}

/*
 *  get_session_name_quiet (no warnings/errors emitted)
 *
 *  Return allocated string with the session name found in the config
 *  directory.
 */
char *get_session_name_quiet(void)
{
	return _get_session_name(1);
}

/*
 *  list_commands
 *
 *  List commands line by line. This is mostly for bash auto completion and to
 *  avoid difficult parsing.
 */
void list_commands(struct cmd_struct *commands, FILE *ofp)
{
	int i = 0;
	struct cmd_struct *cmd = NULL;

	cmd = &commands[i];
	while (cmd->name != NULL) {
		fprintf(ofp, "%s\n", cmd->name);
		i++;
		cmd = &commands[i];
	}
}

/*
 * list_cmd_options
 *
 * Prints a simple list of the options available to a command. This is intended
 * to be easily parsed for bash completion.
 */
void list_cmd_options(FILE *ofp, struct poptOption *options)
{
	int i;
	struct poptOption *option = NULL;

	for (i = 0; options[i].longName != NULL; i++) {
		option = &options[i];

		fprintf(ofp, "--%s\n", option->longName);

		if (isprint(option->shortName)) {
			fprintf(ofp, "-%c\n", option->shortName);
		}
	}
}

/*
 * fls: returns the position of the most significant bit.
 * Returns 0 if no bit is set, else returns the position of the most
 * significant bit (from 1 to 32 on 32-bit, from 1 to 64 on 64-bit).
 */
#if defined(__i386) || defined(__x86_64)
static inline
unsigned int fls_u32(uint32_t x)
{
	int r;

	asm("bsrl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n\t"
	    "1:\n\t"
	    : "=r" (r) : "rm" (x));
	return r + 1;
}
#define HAS_FLS_U32
#endif

#if defined(__x86_64)
static inline
unsigned int fls_u64(uint64_t x)
{
	long r;

	asm("bsrq %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movq $-1,%0\n\t"
	    "1:\n\t"
	    : "=r" (r) : "rm" (x));
	return r + 1;
}
#define HAS_FLS_U64
#endif

#ifndef HAS_FLS_U64
static __attribute__((unused))
unsigned int fls_u64(uint64_t x)
{
	unsigned int r = 64;

	if (!x)
		return 0;

	if (!(x & 0xFFFFFFFF00000000ULL)) {
		x <<= 32;
		r -= 32;
	}
	if (!(x & 0xFFFF000000000000ULL)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF00000000000000ULL)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF000000000000000ULL)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC000000000000000ULL)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x8000000000000000ULL)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}
#endif

#ifndef HAS_FLS_U32
static __attribute__((unused))
unsigned int fls_u32(uint32_t x)
{
	unsigned int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xFFFF0000U)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF000000U)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF0000000U)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC0000000U)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000U)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}
#endif

static
unsigned int fls_ulong(unsigned long x)
{
#if (CAA_BITS_PER_LONG == 32)
	return fls_u32(x);
#else
	return fls_u64(x);
#endif
}

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_u32(uint32_t x)
{
	if (!x)
		return -1;

	return fls_u32(x - 1);
}

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_u64(uint64_t x)
{
	if (!x)
		return -1;

	return fls_u64(x - 1);
}

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_ulong(unsigned long x)
{
	if (!x)
		return -1;

	return fls_ulong(x - 1);
}

const char *get_domain_str(enum lttng_domain_type domain)
{
	const char *str_dom;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		str_dom = str_kernel;
		break;
	case LTTNG_DOMAIN_UST:
		str_dom = str_ust;
		break;
	case LTTNG_DOMAIN_JUL:
		str_dom = str_jul;
		break;
	case LTTNG_DOMAIN_LOG4J:
		str_dom = str_log4j;
		break;
	case LTTNG_DOMAIN_PYTHON:
		str_dom = str_python;
		break;
	default:
		/* Should not have an unknown domain or else define it. */
		assert(0);
	}

	return str_dom;
}

/*
 * Spawn a lttng relayd daemon by forking and execv.
 */
int spawn_relayd(const char *pathname, int port)
{
	int ret = 0;
	pid_t pid;
	char url[255];

	if (!port) {
		port = DEFAULT_NETWORK_VIEWER_PORT;
	}

	ret = snprintf(url, sizeof(url), "tcp://localhost:%d", port);
	if (ret < 0) {
		goto end;
	}

	MSG("Spawning a relayd daemon");
	pid = fork();
	if (pid == 0) {
		/*
		 * Spawn session daemon and tell
		 * it to signal us when ready.
		 */
		execlp(pathname, "lttng-relayd", "-L", url, NULL);
		/* execlp only returns if error happened */
		if (errno == ENOENT) {
			ERR("No relayd found. Use --relayd-path.");
		} else {
			PERROR("execlp");
		}
		kill(getppid(), SIGTERM);	/* wake parent */
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		goto end;
	} else {
		PERROR("fork");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 * Check if relayd is alive.
 *
 * Return 1 if found else 0 if NOT found. Negative value on error.
 */
int check_relayd(void)
{
	int ret, fd;
	struct sockaddr_in sin;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		PERROR("socket check relayd");
		ret = -1;
		goto error_socket;
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(DEFAULT_NETWORK_VIEWER_PORT);
	ret = inet_pton(sin.sin_family, "127.0.0.1", &sin.sin_addr);
	if (ret < 1) {
		PERROR("inet_pton check relayd");
		ret = -1;
		goto error;
	}

	/*
	 * A successful connect means the relayd exists thus returning 0 else a
	 * negative value means it does NOT exists.
	 */
	ret = connect(fd, (struct sockaddr *) &sin, sizeof(sin));
	if (ret < 0) {
		/* Not found. */
		ret = 0;
	} else {
		/* Already spawned. */
		ret = 1;
	}

error:
	if (close(fd) < 0) {
		PERROR("close relayd fd");
	}
error_socket:
	return ret;
}

int print_missing_or_multiple_domains(unsigned int sum)
{
	int ret = 0;

	if (sum == 0) {
		ERR("Please specify a domain (-k/-u/-j).");
		ret = -1;
	} else if (sum > 1) {
		ERR("Multiple domains specified.");
		ret = -1;
	}

	return ret;
}

/*
 * Get the discarded events and lost packet counts.
 */
void print_session_stats(const char *session_name)
{
	int count, nb_domains, domain_idx, channel_idx, session_idx;
	struct lttng_domain *domains;
	struct lttng_channel *channels;
	uint64_t discarded_events_total = 0, lost_packets_total = 0;
	struct lttng_session *sessions = NULL;
	const struct lttng_session *selected_session = NULL;

	count = lttng_list_sessions(&sessions);
	if (count < 1) {
		ERR("Failed to retrieve session descriptions while printing session statistics.");
		goto end;
	}

	/* Identify the currently-selected sessions. */
	for (session_idx = 0; session_idx < count; session_idx++) {
		if (!strcmp(session_name, sessions[session_idx].name)) {
			selected_session = &sessions[session_idx];
			break;
		}
	}
	if (!selected_session) {
		ERR("Failed to retrieve session \"%s\" description while printing session statistics.", session_name);
		goto end;
	}

	nb_domains = lttng_list_domains(session_name, &domains);
	if (nb_domains < 0) {
		goto end;
	}
	for (domain_idx = 0; domain_idx < nb_domains; domain_idx++) {
		struct lttng_handle *handle = lttng_create_handle(session_name,
				&domains[domain_idx]);

		if (!handle) {
			ERR("Failed to create session handle while printing session statistics.");
			goto end;
		}

		count = lttng_list_channels(handle, &channels);
		for (channel_idx = 0; channel_idx < count; channel_idx++) {
			int ret;
			uint64_t discarded_events = 0, lost_packets = 0;
			struct lttng_channel *channel = &channels[channel_idx];

			ret = lttng_channel_get_discarded_event_count(channel,
					&discarded_events);
			if (ret) {
				ERR("Failed to retrieve discarded event count from channel %s",
						channel->name);
			}

			ret = lttng_channel_get_lost_packet_count(channel,
					&lost_packets);
			if (ret) {
				ERR("Failed to retrieve lost packet count from channel %s",
						channel->name);
			}

			discarded_events_total += discarded_events;
			lost_packets_total += lost_packets;
		}
		lttng_destroy_handle(handle);
	}
	if (discarded_events_total > 0 && !selected_session->snapshot_mode) {
		MSG("[warning] %" PRIu64 " events discarded, please refer to "
				"the documentation on channel configuration.",
				discarded_events_total);
	}
	if (lost_packets_total > 0 && !selected_session->snapshot_mode) {
		MSG("[warning] %" PRIu64 " packets lost, please refer to "
				"the documentation on channel configuration.",
				lost_packets_total);
	}

end:
	free(sessions);
}

int show_cmd_help(const char *cmd_name, const char *help_msg)
{
	int ret;
	char page_name[32];

	ret = sprintf(page_name, "lttng-%s", cmd_name);
	assert(ret > 0 && ret < 32);
	ret = utils_show_help(1, page_name, help_msg);
	if (ret && !help_msg) {
		ERR("Cannot view man page `lttng-%s(1)`", cmd_name);
		perror("exec");
	}

	return ret;
}
