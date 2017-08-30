/*
 * liblttngctl.c
 *
 * Linux Trace Toolkit Control Library
 *
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <assert.h>
#include <grp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>
#include <common/utils.h>
#include <lttng/lttng.h>
#include <lttng/health-internal.h>
#include <lttng/trigger/trigger-internal.h>
#include <lttng/endpoint.h>
#include <lttng/channel-internal.h>

#include "filter/filter-ast.h"
#include "filter/filter-parser.h"
#include "filter/filter-bytecode.h"
#include "filter/memstream.h"
#include "lttng-ctl-helper.h"

#ifdef DEBUG
static const int print_xml = 1;
#define dbg_printf(fmt, args...)	\
	printf("[debug liblttng-ctl] " fmt, ## args)
#else
static const int print_xml = 0;
#define dbg_printf(fmt, args...)				\
do {								\
	/* do nothing but check printf format */		\
	if (0)							\
		printf("[debug liblttnctl] " fmt, ## args);	\
} while (0)
#endif


/* Socket to session daemon for communication */
static int sessiond_socket;
static char sessiond_sock_path[PATH_MAX];

/* Variables */
static char *tracing_group;
static int connected;

/* Global */

/*
 * Those two variables are used by error.h to silent or control the verbosity of
 * error message. They are global to the library so application linking with it
 * are able to compile correctly and also control verbosity of the library.
 */
int lttng_opt_quiet;
int lttng_opt_verbose;
int lttng_opt_mi;

/*
 * Copy string from src to dst and enforce null terminated byte.
 */
LTTNG_HIDDEN
void lttng_ctl_copy_string(char *dst, const char *src, size_t len)
{
	if (src && dst) {
		strncpy(dst, src, len);
		/* Enforce the NULL terminated byte */
		dst[len - 1] = '\0';
	} else if (dst) {
		dst[0] = '\0';
	}
}

/*
 * Copy domain to lttcomm_session_msg domain.
 *
 * If domain is unknown, default domain will be the kernel.
 */
LTTNG_HIDDEN
void lttng_ctl_copy_lttng_domain(struct lttng_domain *dst,
		struct lttng_domain *src)
{
	if (src && dst) {
		switch (src->type) {
		case LTTNG_DOMAIN_KERNEL:
		case LTTNG_DOMAIN_UST:
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
			memcpy(dst, src, sizeof(struct lttng_domain));
			break;
		default:
			memset(dst, 0, sizeof(struct lttng_domain));
			break;
		}
	}
}

/*
 * Send lttcomm_session_msg to the session daemon.
 *
 * On success, returns the number of bytes sent (>=0)
 * On error, returns -1
 */
static int send_session_msg(struct lttcomm_session_msg *lsm)
{
	int ret;

	if (!connected) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto end;
	}

	DBG("LSM cmd type : %d", lsm->cmd_type);

	ret = lttcomm_send_creds_unix_sock(sessiond_socket, lsm,
			sizeof(struct lttcomm_session_msg));
	if (ret < 0) {
		ret = -LTTNG_ERR_FATAL;
	}

end:
	return ret;
}

/*
 * Send var len data to the session daemon.
 *
 * On success, returns the number of bytes sent (>=0)
 * On error, returns -1
 */
static int send_session_varlen(const void *data, size_t len)
{
	int ret;

	if (!connected) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto end;
	}

	if (!data || !len) {
		ret = 0;
		goto end;
	}

	ret = lttcomm_send_unix_sock(sessiond_socket, data, len);
	if (ret < 0) {
		ret = -LTTNG_ERR_FATAL;
	}

end:
	return ret;
}

/*
 * Receive data from the sessiond socket.
 *
 * On success, returns the number of bytes received (>=0)
 * On error, returns -1 (recvmsg() error) or -ENOTCONN
 */
static int recv_data_sessiond(void *buf, size_t len)
{
	int ret;

	if (!connected) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto end;
	}

	ret = lttcomm_recv_unix_sock(sessiond_socket, buf, len);
	if (ret < 0) {
		ret = -LTTNG_ERR_FATAL;
	}

end:
	return ret;
}

/*
 * Check if we are in the specified group.
 *
 * If yes return 1, else return -1.
 */
LTTNG_HIDDEN
int lttng_check_tracing_group(void)
{
	struct group *grp_tracing;	/* no free(). See getgrnam(3) */
	gid_t *grp_list;
	int grp_list_size, grp_id, i;
	int ret = -1;
	const char *grp_name = tracing_group;

	/* Get GID of group 'tracing' */
	grp_tracing = getgrnam(grp_name);
	if (!grp_tracing) {
		/* If grp_tracing is NULL, the group does not exist. */
		goto end;
	}

	/* Get number of supplementary group IDs */
	grp_list_size = getgroups(0, NULL);
	if (grp_list_size < 0) {
		PERROR("getgroups");
		goto end;
	}

	/* Alloc group list of the right size */
	grp_list = zmalloc(grp_list_size * sizeof(gid_t));
	if (!grp_list) {
		PERROR("malloc");
		goto end;
	}
	grp_id = getgroups(grp_list_size, grp_list);
	if (grp_id < 0) {
		PERROR("getgroups");
		goto free_list;
	}

	for (i = 0; i < grp_list_size; i++) {
		if (grp_list[i] == grp_tracing->gr_gid) {
			ret = 1;
			break;
		}
	}

free_list:
	free(grp_list);

end:
	return ret;
}

/*
 * Try connect to session daemon with sock_path.
 *
 * Return 0 on success, else -1
 */
static int try_connect_sessiond(const char *sock_path)
{
	int ret;

	/* If socket exist, we check if the daemon listens for connect. */
	ret = access(sock_path, F_OK);
	if (ret < 0) {
		/* Not alive */
		goto error;
	}

	ret = lttcomm_connect_unix_sock(sock_path);
	if (ret < 0) {
		/* Not alive. */
		goto error;
	}

	ret = lttcomm_close_unix_sock(ret);
	if (ret < 0) {
		PERROR("lttcomm_close_unix_sock");
	}

	return 0;

error:
	return -1;
}

/*
 * Set sessiond socket path by putting it in the global sessiond_sock_path
 * variable.
 *
 * Returns 0 on success, negative value on failure (the sessiond socket path
 * is somehow too long or ENOMEM).
 */
static int set_session_daemon_path(void)
{
	int in_tgroup = 0;	/* In tracing group. */
	uid_t uid;

	uid = getuid();

	if (uid != 0) {
		/* Are we in the tracing group ? */
		in_tgroup = lttng_check_tracing_group();
	}

	if ((uid == 0) || in_tgroup) {
		lttng_ctl_copy_string(sessiond_sock_path,
				DEFAULT_GLOBAL_CLIENT_UNIX_SOCK, sizeof(sessiond_sock_path));
	}

	if (uid != 0) {
		int ret;

		if (in_tgroup) {
			/* Tracing group. */
			ret = try_connect_sessiond(sessiond_sock_path);
			if (ret >= 0) {
				goto end;
			}
			/* Global session daemon not available... */
		}
		/* ...or not in tracing group (and not root), default */

		/*
		 * With GNU C <  2.1, snprintf returns -1 if the target buffer
		 * is too small;
		 * With GNU C >= 2.1, snprintf returns the required size
		 * (excluding closing null)
		 */
		ret = snprintf(sessiond_sock_path, sizeof(sessiond_sock_path),
				DEFAULT_HOME_CLIENT_UNIX_SOCK, utils_get_home_dir());
		if ((ret < 0) || (ret >= sizeof(sessiond_sock_path))) {
			goto error;
		}
	}
end:
	return 0;

error:
	return -1;
}

/*
 * Connect to the LTTng session daemon.
 *
 * On success, return 0. On error, return -1.
 */
static int connect_sessiond(void)
{
	int ret;

	/* Don't try to connect if already connected. */
	if (connected) {
		return 0;
	}

	ret = set_session_daemon_path();
	if (ret < 0) {
		goto error;
	}

	/* Connect to the sesssion daemon. */
	ret = lttcomm_connect_unix_sock(sessiond_sock_path);
	if (ret < 0) {
		goto error;
	}

	sessiond_socket = ret;
	connected = 1;

	return 0;

error:
	return -1;
}

/*
 *  Clean disconnect from the session daemon.
 *
 *  On success, return 0. On error, return -1.
 */
static int disconnect_sessiond(void)
{
	int ret = 0;

	if (connected) {
		ret = lttcomm_close_unix_sock(sessiond_socket);
		sessiond_socket = 0;
		connected = 0;
	}

	return ret;
}

static int recv_sessiond_optional_data(size_t len, void **user_buf,
	size_t *user_len)
{
	int ret = 0;
	void *buf = NULL;

	if (len) {
		if (!user_len) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		buf = zmalloc(len);
		if (!buf) {
			ret = -ENOMEM;
			goto end;
		}

		ret = recv_data_sessiond(buf, len);
		if (ret < 0) {
			goto end;
		}

		if (!user_buf) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		/* Move ownership of command header buffer to user. */
		*user_buf = buf;
		buf = NULL;
		*user_len = len;
	} else {
		/* No command header. */
		if (user_len) {
			*user_len = 0;
		}

		if (user_buf) {
			*user_buf = NULL;
		}
	}

end:
	free(buf);
	return ret;
}

/*
 * Ask the session daemon a specific command and put the data into buf.
 * Takes extra var. len. data as input to send to the session daemon.
 *
 * Return size of data (only payload, not header) or a negative error code.
 */
LTTNG_HIDDEN
int lttng_ctl_ask_sessiond_varlen(struct lttcomm_session_msg *lsm,
		const void *vardata, size_t vardata_len,
		void **user_payload_buf, void **user_cmd_header_buf,
		size_t *user_cmd_header_len)
{
	int ret;
	size_t payload_len;
	struct lttcomm_lttng_msg llm;

	ret = connect_sessiond();
	if (ret < 0) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto end;
	}

	/* Send command to session daemon */
	ret = send_session_msg(lsm);
	if (ret < 0) {
		/* Ret value is a valid lttng error code. */
		goto end;
	}
	/* Send var len data */
	ret = send_session_varlen(vardata, vardata_len);
	if (ret < 0) {
		/* Ret value is a valid lttng error code. */
		goto end;
	}

	/* Get header from data transmission */
	ret = recv_data_sessiond(&llm, sizeof(llm));
	if (ret < 0) {
		/* Ret value is a valid lttng error code. */
		goto end;
	}

	/* Check error code if OK */
	if (llm.ret_code != LTTNG_OK) {
		ret = -llm.ret_code;
		goto end;
	}

	/* Get command header from data transmission */
	ret = recv_sessiond_optional_data(llm.cmd_header_size,
		user_cmd_header_buf, user_cmd_header_len);
	if (ret < 0) {
		goto end;
	}

	/* Get payload from data transmission */
	ret = recv_sessiond_optional_data(llm.data_size, user_payload_buf,
		&payload_len);
	if (ret < 0) {
		goto end;
	}

	ret = llm.data_size;

end:
	disconnect_sessiond();
	return ret;
}

/*
 * Create lttng handle and return pointer.
 *
 * The returned pointer will be NULL in case of malloc() error.
 */
struct lttng_handle *lttng_create_handle(const char *session_name,
		struct lttng_domain *domain)
{
	struct lttng_handle *handle = NULL;

	handle = zmalloc(sizeof(struct lttng_handle));
	if (handle == NULL) {
		PERROR("malloc handle");
		goto end;
	}

	/* Copy session name */
	lttng_ctl_copy_string(handle->session_name, session_name,
			sizeof(handle->session_name));

	/* Copy lttng domain or leave initialized to 0. */
	if (domain) {
		lttng_ctl_copy_lttng_domain(&handle->domain, domain);
	}

end:
	return handle;
}

/*
 * Destroy handle by free(3) the pointer.
 */
void lttng_destroy_handle(struct lttng_handle *handle)
{
	free(handle);
}

/*
 * Register an outside consumer.
 *
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_register_consumer(struct lttng_handle *handle,
		const char *socket_path)
{
	struct lttcomm_session_msg lsm;

	if (handle == NULL || socket_path == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_REGISTER_CONSUMER;
	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	lttng_ctl_copy_string(lsm.u.reg.path, socket_path,
			sizeof(lsm.u.reg.path));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Start tracing for all traces of the session.
 *
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_start_tracing(const char *session_name)
{
	struct lttcomm_session_msg lsm;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_START_TRACE;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Stop tracing for all traces of the session.
 */
static int _lttng_stop_tracing(const char *session_name, int wait)
{
	int ret, data_ret;
	struct lttcomm_session_msg lsm;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_STOP_TRACE;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, NULL);
	if (ret < 0 && ret != -LTTNG_ERR_TRACE_ALREADY_STOPPED) {
		goto error;
	}

	if (!wait) {
		goto end;
	}

	/* Check for data availability */
	do {
		data_ret = lttng_data_pending(session_name);
		if (data_ret < 0) {
			/* Return the data available call error. */
			ret = data_ret;
			goto error;
		}

		/*
		 * Data sleep time before retrying (in usec). Don't sleep if the
		 * call returned value indicates availability.
		 */
		if (data_ret) {
			usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME);
		}
	} while (data_ret != 0);

end:
error:
	return ret;
}

/*
 * Stop tracing and wait for data availability.
 */
int lttng_stop_tracing(const char *session_name)
{
	return _lttng_stop_tracing(session_name, 1);
}

/*
 * Stop tracing but _don't_ wait for data availability.
 */
int lttng_stop_tracing_no_wait(const char *session_name)
{
	return _lttng_stop_tracing(session_name, 0);
}

/*
 * Add context to a channel.
 *
 * If the given channel is NULL, add the contexts to all channels.
 * The event_name param is ignored.
 *
 * Returns the size of the returned payload data or a negative error code.
 */
int lttng_add_context(struct lttng_handle *handle,
		struct lttng_event_context *ctx, const char *event_name,
		const char *channel_name)
{
	int ret;
	size_t len = 0;
	char *buf = NULL;
	struct lttcomm_session_msg lsm;

	/* Safety check. Both are mandatory. */
	if (handle == NULL || ctx == NULL) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_ADD_CONTEXT;

	/* If no channel name, send empty string. */
	if (channel_name == NULL) {
		lttng_ctl_copy_string(lsm.u.context.channel_name, "",
				sizeof(lsm.u.context.channel_name));
	} else {
		lttng_ctl_copy_string(lsm.u.context.channel_name, channel_name,
				sizeof(lsm.u.context.channel_name));
	}

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);
	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	if (ctx->ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
		size_t provider_len, ctx_len;
		const char *provider_name = ctx->u.app_ctx.provider_name;
		const char *ctx_name = ctx->u.app_ctx.ctx_name;

		if (!provider_name || !ctx_name) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		provider_len = strlen(provider_name);
		if (provider_len == 0) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		lsm.u.context.provider_name_len = provider_len;

		ctx_len = strlen(ctx_name);
		if (ctx_len == 0) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		lsm.u.context.context_name_len = ctx_len;

		len = provider_len + ctx_len;
		buf = zmalloc(len);
		if (!buf) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		memcpy(buf, provider_name, provider_len);
		memcpy(buf + provider_len, ctx_name, ctx_len);
	}
	memcpy(&lsm.u.context.ctx, ctx, sizeof(struct lttng_event_context));

	if (ctx->ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
		/*
		 * Don't leak application addresses to the sessiond.
		 * This is only necessary when ctx is for an app ctx otherwise
		 * the values inside the union (type & config) are overwritten.
		 */
		lsm.u.context.ctx.u.app_ctx.provider_name = NULL;
		lsm.u.context.ctx.u.app_ctx.ctx_name = NULL;
	}

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, buf, len, NULL);
end:
	free(buf);
	return ret;
}

/*
 * Enable event(s) for a channel.
 *
 * If no event name is specified, all events are enabled.
 * If no channel name is specified, the default 'channel0' is used.
 *
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_enable_event(struct lttng_handle *handle,
		struct lttng_event *ev, const char *channel_name)
{
	return lttng_enable_event_with_exclusions(handle, ev, channel_name,
			NULL, 0, NULL);
}

/*
 * Create or enable an event with a filter expression.
 *
 * Return negative error value on error.
 * Return size of returned session payload data if OK.
 */
int lttng_enable_event_with_filter(struct lttng_handle *handle,
		struct lttng_event *event, const char *channel_name,
		const char *filter_expression)
{
	return lttng_enable_event_with_exclusions(handle, event, channel_name,
			filter_expression, 0, NULL);
}

/*
 * Depending on the event, return a newly allocated agent filter expression or
 * NULL if not applicable.
 *
 * An event with NO loglevel and the name is * will return NULL.
 */
static char *set_agent_filter(const char *filter, struct lttng_event *ev)
{
	int err;
	char *agent_filter = NULL;

	assert(ev);

	/* Don't add filter for the '*' event. */
	if (strcmp(ev->name, "*") != 0) {
		if (filter) {
			err = asprintf(&agent_filter, "(%s) && (logger_name == \"%s\")", filter,
					ev->name);
		} else {
			err = asprintf(&agent_filter, "logger_name == \"%s\"", ev->name);
		}
		if (err < 0) {
			PERROR("asprintf");
			goto error;
		}
	}

	/* Add loglevel filtering if any for the JUL domain. */
	if (ev->loglevel_type != LTTNG_EVENT_LOGLEVEL_ALL) {
		char *op;

		if (ev->loglevel_type == LTTNG_EVENT_LOGLEVEL_RANGE) {
			op = ">=";
		} else {
			op = "==";
		}

		if (filter || agent_filter) {
			char *new_filter;

			err = asprintf(&new_filter, "(%s) && (int_loglevel %s %d)",
					agent_filter ? agent_filter : filter, op,
					ev->loglevel);
			if (agent_filter) {
				free(agent_filter);
			}
			agent_filter = new_filter;
		} else {
			err = asprintf(&agent_filter, "int_loglevel %s %d", op,
					ev->loglevel);
		}
		if (err < 0) {
			PERROR("asprintf");
			goto error;
		}
	}

	return agent_filter;
error:
	free(agent_filter);
	return NULL;
}

/*
 * Generate the filter bytecode from a given filter expression string. Put the
 * newly allocated parser context in ctxp and populate the lsm object with the
 * expression len.
 *
 * Return 0 on success else a LTTNG_ERR_* code and ctxp is untouched.
 */
static int generate_filter(char *filter_expression,
		struct lttcomm_session_msg *lsm, struct filter_parser_ctx **ctxp)
{
	int ret;
	struct filter_parser_ctx *ctx = NULL;
	FILE *fmem = NULL;

	assert(filter_expression);
	assert(lsm);
	assert(ctxp);

	/*
	 * Casting const to non-const, as the underlying function will use it in
	 * read-only mode.
	 */
	fmem = lttng_fmemopen((void *) filter_expression,
			strlen(filter_expression), "r");
	if (!fmem) {
		fprintf(stderr, "Error opening memory as stream\n");
		ret = -LTTNG_ERR_FILTER_NOMEM;
		goto error;
	}
	ctx = filter_parser_ctx_alloc(fmem);
	if (!ctx) {
		fprintf(stderr, "Error allocating parser\n");
		ret = -LTTNG_ERR_FILTER_NOMEM;
		goto filter_alloc_error;
	}
	ret = filter_parser_ctx_append_ast(ctx);
	if (ret) {
		fprintf(stderr, "Parse error\n");
		ret = -LTTNG_ERR_FILTER_INVAL;
		goto parse_error;
	}
	ret = filter_visitor_set_parent(ctx);
	if (ret) {
		fprintf(stderr, "Set parent error\n");
		ret = -LTTNG_ERR_FILTER_INVAL;
		goto parse_error;
	}
	if (print_xml) {
		ret = filter_visitor_print_xml(ctx, stdout, 0);
		if (ret) {
			fflush(stdout);
			fprintf(stderr, "XML print error\n");
			ret = -LTTNG_ERR_FILTER_INVAL;
			goto parse_error;
		}
	}

	dbg_printf("Generating IR... ");
	fflush(stdout);
	ret = filter_visitor_ir_generate(ctx);
	if (ret) {
		fprintf(stderr, "Generate IR error\n");
		ret = -LTTNG_ERR_FILTER_INVAL;
		goto parse_error;
	}
	dbg_printf("done\n");

	dbg_printf("Validating IR... ");
	fflush(stdout);
	ret = filter_visitor_ir_check_binary_op_nesting(ctx);
	if (ret) {
		ret = -LTTNG_ERR_FILTER_INVAL;
		goto parse_error;
	}

	/* Normalize globbing patterns in the expression. */
	ret = filter_visitor_ir_normalize_glob_patterns(ctx);
	if (ret) {
		ret = -LTTNG_ERR_FILTER_INVAL;
		goto parse_error;
	}

	/* Validate strings used as literals in the expression. */
	ret = filter_visitor_ir_validate_string(ctx);
	if (ret) {
		ret = -LTTNG_ERR_FILTER_INVAL;
		goto parse_error;
	}

	/* Validate globbing patterns in the expression. */
	ret = filter_visitor_ir_validate_globbing(ctx);
	if (ret) {
		ret = -LTTNG_ERR_FILTER_INVAL;
		goto parse_error;
	}

	dbg_printf("done\n");

	dbg_printf("Generating bytecode... ");
	fflush(stdout);
	ret = filter_visitor_bytecode_generate(ctx);
	if (ret) {
		fprintf(stderr, "Generate bytecode error\n");
		ret = -LTTNG_ERR_FILTER_INVAL;
		goto parse_error;
	}
	dbg_printf("done\n");
	dbg_printf("Size of bytecode generated: %u bytes.\n",
			bytecode_get_len(&ctx->bytecode->b));

	lsm->u.enable.bytecode_len = sizeof(ctx->bytecode->b)
		+ bytecode_get_len(&ctx->bytecode->b);
	lsm->u.enable.expression_len = strlen(filter_expression) + 1;

	/* No need to keep the memory stream. */
	if (fclose(fmem) != 0) {
		PERROR("fclose");
	}

	*ctxp = ctx;
	return 0;

parse_error:
	filter_ir_free(ctx);
	filter_parser_ctx_free(ctx);
filter_alloc_error:
	if (fclose(fmem) != 0) {
		PERROR("fclose");
	}
error:
	return ret;
}

/*
 * Enable event(s) for a channel, possibly with exclusions and a filter.
 * If no event name is specified, all events are enabled.
 * If no channel name is specified, the default name is used.
 * If filter expression is not NULL, the filter is set for the event.
 * If exclusion count is not zero, the exclusions are set for the event.
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_enable_event_with_exclusions(struct lttng_handle *handle,
		struct lttng_event *ev, const char *channel_name,
		const char *original_filter_expression,
		int exclusion_count, char **exclusion_list)
{
	struct lttcomm_session_msg lsm;
	char *varlen_data;
	int ret = 0;
	unsigned int free_filter_expression = 0;
	struct filter_parser_ctx *ctx = NULL;
	/*
	 * Cast as non-const since we may replace the filter expression
	 * by a dynamically allocated string. Otherwise, the original
	 * string is not modified.
	 */
	char *filter_expression = (char *) original_filter_expression;

	if (handle == NULL || ev == NULL) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	/*
	 * Empty filter string will always be rejected by the parser
	 * anyway, so treat this corner-case early to eliminate
	 * lttng_fmemopen error for 0-byte allocation.
	 */
	if (filter_expression && filter_expression[0] == '\0') {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	memset(&lsm, 0, sizeof(lsm));

	/* If no channel name, send empty string. */
	if (channel_name == NULL) {
		lttng_ctl_copy_string(lsm.u.enable.channel_name, "",
				sizeof(lsm.u.enable.channel_name));
	} else {
		lttng_ctl_copy_string(lsm.u.enable.channel_name, channel_name,
				sizeof(lsm.u.enable.channel_name));
	}

	lsm.cmd_type = LTTNG_ENABLE_EVENT;
	if (ev->name[0] == '\0') {
		/* Enable all events */
		lttng_ctl_copy_string(ev->name, "*", sizeof(ev->name));
	}

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);
	/* FIXME: copying non-packed struct to packed struct. */
	memcpy(&lsm.u.enable.event, ev, sizeof(lsm.u.enable.event));

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));
	lsm.u.enable.exclusion_count = exclusion_count;
	lsm.u.enable.bytecode_len = 0;

	/*
	 * For the JUL domain, a filter is enforced except for the enable all
	 * event. This is done to avoid having the event in all sessions thus
	 * filtering by logger name.
	 */
	if (exclusion_count == 0 && filter_expression == NULL &&
			(handle->domain.type != LTTNG_DOMAIN_JUL &&
				handle->domain.type != LTTNG_DOMAIN_LOG4J &&
				handle->domain.type != LTTNG_DOMAIN_PYTHON)) {
		goto ask_sessiond;
	}

	/*
	 * We have either a filter or some exclusions, so we need to set up
	 * a variable-length memory block from where to send the data.
	 */

	/* Parse filter expression. */
	if (filter_expression != NULL || handle->domain.type == LTTNG_DOMAIN_JUL
			|| handle->domain.type == LTTNG_DOMAIN_LOG4J
			|| handle->domain.type == LTTNG_DOMAIN_PYTHON) {
		if (handle->domain.type == LTTNG_DOMAIN_JUL ||
				handle->domain.type == LTTNG_DOMAIN_LOG4J ||
				handle->domain.type == LTTNG_DOMAIN_PYTHON) {
			char *agent_filter;

			/* Setup JUL filter if needed. */
			agent_filter = set_agent_filter(filter_expression, ev);
			if (!agent_filter) {
				if (!filter_expression) {
					/*
					 * No JUL and no filter, just skip
					 * everything below.
					 */
					goto ask_sessiond;
				}
			} else {
				/*
				 * With an agent filter, the original filter has
				 * been added to it thus replace the filter
				 * expression.
				 */
				filter_expression = agent_filter;
				free_filter_expression = 1;
			}
		}

		ret = generate_filter(filter_expression, &lsm, &ctx);
		if (ret) {
			goto filter_error;
		}
	}

	varlen_data = zmalloc(lsm.u.enable.bytecode_len
			+ lsm.u.enable.expression_len
			+ LTTNG_SYMBOL_NAME_LEN * exclusion_count);
	if (!varlen_data) {
		ret = -LTTNG_ERR_EXCLUSION_NOMEM;
		goto mem_error;
	}

	/* Put exclusion names first in the data. */
	while (exclusion_count--) {
		strncpy(varlen_data + LTTNG_SYMBOL_NAME_LEN * exclusion_count,
			*(exclusion_list + exclusion_count),
			LTTNG_SYMBOL_NAME_LEN - 1);
	}
	/* Add filter expression next. */
	if (lsm.u.enable.expression_len != 0) {
		memcpy(varlen_data
			+ LTTNG_SYMBOL_NAME_LEN * lsm.u.enable.exclusion_count,
			filter_expression,
			lsm.u.enable.expression_len);
	}
	/* Add filter bytecode next. */
	if (ctx && lsm.u.enable.bytecode_len != 0) {
		memcpy(varlen_data
			+ LTTNG_SYMBOL_NAME_LEN * lsm.u.enable.exclusion_count
			+ lsm.u.enable.expression_len,
			&ctx->bytecode->b,
			lsm.u.enable.bytecode_len);
	}

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, varlen_data,
			(LTTNG_SYMBOL_NAME_LEN * lsm.u.enable.exclusion_count) +
			lsm.u.enable.bytecode_len + lsm.u.enable.expression_len,
			NULL);
	free(varlen_data);

mem_error:
	if (filter_expression && ctx) {
		filter_bytecode_free(ctx);
		filter_ir_free(ctx);
		filter_parser_ctx_free(ctx);
	}
filter_error:
	if (free_filter_expression) {
		/*
		 * The filter expression has been replaced and must be freed as
		 * it is not the original filter expression received as a
		 * parameter.
		 */
		free(filter_expression);
	}
error:
	/*
	 * Return directly to the caller and don't ask the sessiond since
	 * something went wrong in the parsing of data above.
	 */
	return ret;

ask_sessiond:
	ret = lttng_ctl_ask_sessiond(&lsm, NULL);
	return ret;
}

int lttng_disable_event_ext(struct lttng_handle *handle,
		struct lttng_event *ev, const char *channel_name,
		const char *original_filter_expression)
{
	struct lttcomm_session_msg lsm;
	char *varlen_data;
	int ret = 0;
	unsigned int free_filter_expression = 0;
	struct filter_parser_ctx *ctx = NULL;
	/*
	 * Cast as non-const since we may replace the filter expression
	 * by a dynamically allocated string. Otherwise, the original
	 * string is not modified.
	 */
	char *filter_expression = (char *) original_filter_expression;

	if (handle == NULL || ev == NULL) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	/*
	 * Empty filter string will always be rejected by the parser
	 * anyway, so treat this corner-case early to eliminate
	 * lttng_fmemopen error for 0-byte allocation.
	 */
	if (filter_expression && filter_expression[0] == '\0') {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	memset(&lsm, 0, sizeof(lsm));

	/* If no channel name, send empty string. */
	if (channel_name == NULL) {
		lttng_ctl_copy_string(lsm.u.disable.channel_name, "",
				sizeof(lsm.u.disable.channel_name));
	} else {
		lttng_ctl_copy_string(lsm.u.disable.channel_name, channel_name,
				sizeof(lsm.u.disable.channel_name));
	}

	lsm.cmd_type = LTTNG_DISABLE_EVENT;

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);
	/* FIXME: copying non-packed struct to packed struct. */
	memcpy(&lsm.u.disable.event, ev, sizeof(lsm.u.disable.event));

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));
	lsm.u.disable.bytecode_len = 0;

	/*
	 * For the JUL domain, a filter is enforced except for the
	 * disable all event. This is done to avoid having the event in
	 * all sessions thus filtering by logger name.
	 */
	if (filter_expression == NULL &&
			(handle->domain.type != LTTNG_DOMAIN_JUL &&
				handle->domain.type != LTTNG_DOMAIN_LOG4J &&
				handle->domain.type != LTTNG_DOMAIN_PYTHON)) {
		goto ask_sessiond;
	}

	/*
	 * We have a filter, so we need to set up a variable-length
	 * memory block from where to send the data.
	 */

	/* Parse filter expression */
	if (filter_expression != NULL || handle->domain.type == LTTNG_DOMAIN_JUL
			|| handle->domain.type == LTTNG_DOMAIN_LOG4J
			|| handle->domain.type == LTTNG_DOMAIN_PYTHON) {
		if (handle->domain.type == LTTNG_DOMAIN_JUL ||
				handle->domain.type == LTTNG_DOMAIN_LOG4J ||
				handle->domain.type == LTTNG_DOMAIN_PYTHON) {
			char *agent_filter;

			/* Setup JUL filter if needed. */
			agent_filter = set_agent_filter(filter_expression, ev);
			if (!agent_filter) {
				if (!filter_expression) {
					/*
					 * No JUL and no filter, just skip
					 * everything below.
					 */
					goto ask_sessiond;
				}
			} else {
				/*
				 * With a JUL filter, the original filter has
				 * been added to it thus replace the filter
				 * expression.
				 */
				filter_expression = agent_filter;
				free_filter_expression = 1;
			}
		}

		ret = generate_filter(filter_expression, &lsm, &ctx);
		if (ret) {
			goto filter_error;
		}
	}

	varlen_data = zmalloc(lsm.u.disable.bytecode_len
			+ lsm.u.disable.expression_len);
	if (!varlen_data) {
		ret = -LTTNG_ERR_EXCLUSION_NOMEM;
		goto mem_error;
	}

	/* Add filter expression. */
	if (lsm.u.disable.expression_len != 0) {
		memcpy(varlen_data,
			filter_expression,
			lsm.u.disable.expression_len);
	}
	/* Add filter bytecode next. */
	if (ctx && lsm.u.disable.bytecode_len != 0) {
		memcpy(varlen_data
			+ lsm.u.disable.expression_len,
			&ctx->bytecode->b,
			lsm.u.disable.bytecode_len);
	}

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, varlen_data,
			lsm.u.disable.bytecode_len + lsm.u.disable.expression_len, NULL);
	free(varlen_data);

mem_error:
	if (filter_expression && ctx) {
		filter_bytecode_free(ctx);
		filter_ir_free(ctx);
		filter_parser_ctx_free(ctx);
	}
filter_error:
	if (free_filter_expression) {
		/*
		 * The filter expression has been replaced and must be freed as
		 * it is not the original filter expression received as a
		 * parameter.
		 */
		free(filter_expression);
	}
error:
	/*
	 * Return directly to the caller and don't ask the sessiond since
	 * something went wrong in the parsing of data above.
	 */
	return ret;

ask_sessiond:
	ret = lttng_ctl_ask_sessiond(&lsm, NULL);
	return ret;
}

/*
 * Disable event(s) of a channel and domain.
 * If no event name is specified, all events are disabled.
 * If no channel name is specified, the default 'channel0' is used.
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_disable_event(struct lttng_handle *handle, const char *name,
		const char *channel_name)
{
	struct lttng_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.loglevel = -1;
	ev.type = LTTNG_EVENT_ALL;
	lttng_ctl_copy_string(ev.name, name, sizeof(ev.name));
	return lttng_disable_event_ext(handle, &ev, channel_name, NULL);
}

struct lttng_channel *lttng_channel_create(struct lttng_domain *domain)
{
	struct lttng_channel *channel = NULL;
	struct lttng_channel_extended *extended = NULL;

	if (!domain) {
		goto error;
	}

	/* Validate domain. */
	switch (domain->type) {
	case LTTNG_DOMAIN_UST:
		switch (domain->buf_type) {
		case LTTNG_BUFFER_PER_UID:
		case LTTNG_BUFFER_PER_PID:
			break;
		default:
			goto error;
		}
		break;
	case LTTNG_DOMAIN_KERNEL:
		if (domain->buf_type != LTTNG_BUFFER_GLOBAL) {
			goto error;
		}
		break;
	default:
		goto error;
	}

	channel = zmalloc(sizeof(*channel));
	if (!channel) {
		goto error;
	}

	extended = zmalloc(sizeof(*extended));
	if (!extended) {
		goto error;
	}

	channel->attr.extended.ptr = extended;

	lttng_channel_set_default_attr(domain, &channel->attr);
	return channel;
error:
	free(channel);
	free(extended);
	return NULL;
}

void lttng_channel_destroy(struct lttng_channel *channel)
{
	if (!channel) {
		return;
	}

	if (channel->attr.extended.ptr) {
		free(channel->attr.extended.ptr);
	}
	free(channel);
}

/*
 * Enable channel per domain
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_enable_channel(struct lttng_handle *handle,
		struct lttng_channel *in_chan)
{
	struct lttcomm_session_msg lsm;

	/* NULL arguments are forbidden. No default values. */
	if (handle == NULL || in_chan == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	memcpy(&lsm.u.channel.chan, in_chan, sizeof(lsm.u.channel.chan));
	lsm.u.channel.chan.attr.extended.ptr = NULL;

	if (!in_chan->attr.extended.ptr) {
		struct lttng_channel *channel;
		struct lttng_channel_extended *extended;

		channel = lttng_channel_create(&handle->domain);
		if (!channel) {
			return -LTTNG_ERR_NOMEM;
		}

		/*
		 * Create a new channel in order to use default extended
		 * attribute values.
		 */
		extended = (struct lttng_channel_extended *)
				channel->attr.extended.ptr;
		memcpy(&lsm.u.channel.extended, extended, sizeof(*extended));
		lttng_channel_destroy(channel);
	} else {
		struct lttng_channel_extended *extended;

		extended = (struct lttng_channel_extended *)
				in_chan->attr.extended.ptr;
		memcpy(&lsm.u.channel.extended, extended, sizeof(*extended));
	}

	lsm.cmd_type = LTTNG_ENABLE_CHANNEL;
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * All tracing will be stopped for registered events of the channel.
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_disable_channel(struct lttng_handle *handle, const char *name)
{
	struct lttcomm_session_msg lsm;

	/* Safety check. Both are mandatory. */
	if (handle == NULL || name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_DISABLE_CHANNEL;

	lttng_ctl_copy_string(lsm.u.disable.channel_name, name,
			sizeof(lsm.u.disable.channel_name));

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Add PID to session tracker.
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_track_pid(struct lttng_handle *handle, int pid)
{
	struct lttcomm_session_msg lsm;

	/* NULL arguments are forbidden. No default values. */
	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_TRACK_PID;
	lsm.u.pid_tracker.pid = pid;

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Remove PID from session tracker.
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_untrack_pid(struct lttng_handle *handle, int pid)
{
	struct lttcomm_session_msg lsm;

	/* NULL arguments are forbidden. No default values. */
	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_UNTRACK_PID;
	lsm.u.pid_tracker.pid = pid;

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Lists all available tracepoints of domain.
 * Sets the contents of the events array.
 * Returns the number of lttng_event entries in events;
 * on error, returns a negative value.
 */
int lttng_list_tracepoints(struct lttng_handle *handle,
		struct lttng_event **events)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_LIST_TRACEPOINTS;
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) events);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_event);
}

/*
 * Lists all available tracepoint fields of domain.
 * Sets the contents of the event field array.
 * Returns the number of lttng_event_field entries in events;
 * on error, returns a negative value.
 */
int lttng_list_tracepoint_fields(struct lttng_handle *handle,
		struct lttng_event_field **fields)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_LIST_TRACEPOINT_FIELDS;
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) fields);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_event_field);
}

/*
 * Lists all available kernel system calls. Allocates and sets the contents of
 * the events array.
 *
 * Returns the number of lttng_event entries in events; on error, returns a
 * negative value.
 */
int lttng_list_syscalls(struct lttng_event **events)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (!events) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_LIST_SYSCALLS;
	/* Force kernel domain for system calls. */
	lsm.domain.type = LTTNG_DOMAIN_KERNEL;

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) events);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_event);
}

/*
 * Returns a human readable string describing
 * the error code (a negative value).
 */
const char *lttng_strerror(int code)
{
	return error_get_str(code);
}

/*
 * Create a brand new session using name and url for destination.
 *
 * Returns LTTNG_OK on success or a negative error code.
 */
int lttng_create_session(const char *name, const char *url)
{
	int ret;
	ssize_t size;
	struct lttcomm_session_msg lsm;
	struct lttng_uri *uris = NULL;

	if (name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_CREATE_SESSION;
	lttng_ctl_copy_string(lsm.session.name, name, sizeof(lsm.session.name));

	/* There should never be a data URL */
	size = uri_parse_str_urls(url, NULL, &uris);
	if (size < 0) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.u.uri.size = size;

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, uris,
			sizeof(struct lttng_uri) * size, NULL);

	free(uris);
	return ret;
}

/*
 * Destroy session using name.
 * Returns size of returned session payload data or a negative error code.
 */
static
int _lttng_destroy_session(const char *session_name)
{
	struct lttcomm_session_msg lsm;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_DESTROY_SESSION;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Stop the session and wait for the data before destroying it
 */
int lttng_destroy_session(const char *session_name)
{
	int ret;

	/*
	 * Stop the tracing and wait for the data.
	 */
	ret = _lttng_stop_tracing(session_name, 1);
	if (ret && ret != -LTTNG_ERR_TRACE_ALREADY_STOPPED) {
		goto end;
	}

	ret = _lttng_destroy_session(session_name);
end:
	return ret;
}

/*
 * Destroy the session without waiting for the data.
 */
int lttng_destroy_session_no_wait(const char *session_name)
{
	int ret;

	/*
	 * Stop the tracing without waiting for the data.
	 * The session might already have been stopped, so just
	 * skip this error.
	 */
	ret = _lttng_stop_tracing(session_name, 0);
	if (ret && ret != -LTTNG_ERR_TRACE_ALREADY_STOPPED) {
		goto end;
	}

	ret = _lttng_destroy_session(session_name);
end:
	return ret;
}

/*
 * Ask the session daemon for all available sessions.
 * Sets the contents of the sessions array.
 * Returns the number of lttng_session entries in sessions;
 * on error, returns a negative value.
 */
int lttng_list_sessions(struct lttng_session **sessions)
{
	int ret;
	struct lttcomm_session_msg lsm;

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_LIST_SESSIONS;
	ret = lttng_ctl_ask_sessiond(&lsm, (void**) sessions);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_session);
}

int lttng_set_session_shm_path(const char *session_name,
		const char *shm_path)
{
	struct lttcomm_session_msg lsm;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_SET_SESSION_SHM_PATH;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));
	lttng_ctl_copy_string(lsm.u.set_shm_path.shm_path, shm_path,
			sizeof(lsm.u.set_shm_path.shm_path));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Ask the session daemon for all available domains of a session.
 * Sets the contents of the domains array.
 * Returns the number of lttng_domain entries in domains;
 * on error, returns a negative value.
 */
int lttng_list_domains(const char *session_name,
		struct lttng_domain **domains)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_LIST_DOMAINS;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, (void**) domains);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_domain);
}

/*
 * Ask the session daemon for all available channels of a session.
 * Sets the contents of the channels array.
 * Returns the number of lttng_channel entries in channels;
 * on error, returns a negative value.
 */
int lttng_list_channels(struct lttng_handle *handle,
		struct lttng_channel **channels)
{
	int ret;
	size_t channel_count, i;
	const size_t channel_size = sizeof(struct lttng_channel) +
			sizeof(struct lttng_channel_extended);
	struct lttcomm_session_msg lsm;
	void *extended_at;

	if (handle == NULL) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_LIST_CHANNELS;
	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond(&lsm, (void**) channels);
	if (ret < 0) {
		goto end;
	}

	if (ret % channel_size) {
		ret = -LTTNG_ERR_UNK;
		free(*channels);
		*channels = NULL;
		goto end;
	}
	channel_count = (size_t) ret / channel_size;

	/* Set extended info pointers */
	extended_at = ((void *) *channels) +
			channel_count * sizeof(struct lttng_channel);
	for (i = 0; i < channel_count; i++) {
		struct lttng_channel *chan = &(*channels)[i];

		chan->attr.extended.ptr = extended_at;
		extended_at += sizeof(struct lttng_channel_extended);
	}

	ret = (int) channel_count;
end:
	return ret;
}

/*
 * Ask the session daemon for all available events of a session channel.
 * Sets the contents of the events array.
 * Returns the number of lttng_event entries in events;
 * on error, returns a negative value.
 */
int lttng_list_events(struct lttng_handle *handle,
		const char *channel_name, struct lttng_event **events)
{
	int ret;
	struct lttcomm_session_msg lsm;
	struct lttcomm_event_command_header *cmd_header = NULL;
	size_t cmd_header_len;
	uint32_t nb_events, i;
	void *extended_at;

	/* Safety check. An handle and channel name are mandatory */
	if (handle == NULL || channel_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_LIST_EVENTS;
	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));
	lttng_ctl_copy_string(lsm.u.list.channel_name, channel_name,
			sizeof(lsm.u.list.channel_name));
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond_varlen(&lsm, NULL, 0, (void **) events,
		(void **) &cmd_header, &cmd_header_len);
	if (ret < 0) {
		goto error;
	}

	/* Set number of events and free command header */
	nb_events = cmd_header->nb_events;
	if (nb_events > INT_MAX) {
		ret = -EOVERFLOW;
		goto error;
	}
	ret = (int) nb_events;
	free(cmd_header);
	cmd_header = NULL;

	/* Set extended info pointers */
	extended_at = ((void*) (*events)) +
			nb_events * sizeof(struct lttng_event);

	for (i = 0; i < nb_events; i++) {
		struct lttcomm_event_extended_header *ext_header;
		struct lttng_event *event = &(*events)[i];

		event->extended.ptr = extended_at;
		ext_header =
			(struct lttcomm_event_extended_header *) extended_at;
		extended_at += sizeof(*ext_header);
		extended_at += ext_header->filter_len;
		extended_at +=
			ext_header->nb_exclusions * LTTNG_SYMBOL_NAME_LEN;
	}

	return ret;
error:
	free(cmd_header);
	free(*events);
	return ret;
}

int lttng_event_get_filter_expression(struct lttng_event *event,
	const char **filter_expression)
{
	int ret = 0;
	struct lttcomm_event_extended_header *ext_header;

	if (!event || !filter_expression) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ext_header = event->extended.ptr;

	if (!ext_header) {
		/*
		 * This can happen since the lttng_event structure is
		 * used for other tasks where this pointer is never set.
		 */
		*filter_expression = NULL;
		goto end;
	}

	if (ext_header->filter_len) {
		*filter_expression = ((const char *) (ext_header)) +
				sizeof(*ext_header);
	} else {
		*filter_expression = NULL;
	}

end:
	return ret;
}

int lttng_event_get_exclusion_name_count(struct lttng_event *event)
{
	int ret;
	struct lttcomm_event_extended_header *ext_header;

	if (!event) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ext_header = event->extended.ptr;
	if (!ext_header) {
		/*
		 * This can happen since the lttng_event structure is
		 * used for other tasks where this pointer is never set.
		 */
		ret = 0;
		goto end;
	}

	if (ext_header->nb_exclusions > INT_MAX) {
		ret = -LTTNG_ERR_OVERFLOW;
		goto end;
	}
	ret = (int) ext_header->nb_exclusions;
end:
	return ret;
}

int lttng_event_get_exclusion_name(struct lttng_event *event,
		size_t index, const char **exclusion_name)
{
	int ret = 0;
	struct lttcomm_event_extended_header *ext_header;
	void *at;

	if (!event || !exclusion_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ext_header = event->extended.ptr;
	if (!ext_header) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (index >= ext_header->nb_exclusions) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	at = (void *) ext_header + sizeof(*ext_header);
	at += ext_header->filter_len;
	at += index * LTTNG_SYMBOL_NAME_LEN;
	*exclusion_name = at;

end:
	return ret;
}

/*
 * Sets the tracing_group variable with name.
 * This function allocates memory pointed to by tracing_group.
 * On success, returns 0, on error, returns -1 (null name) or -ENOMEM.
 */
int lttng_set_tracing_group(const char *name)
{
	if (name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	if (asprintf(&tracing_group, "%s", name) < 0) {
		return -LTTNG_ERR_FATAL;
	}

	return 0;
}

int lttng_calibrate(struct lttng_handle *handle,
		struct lttng_calibrate *calibrate)
{
	/*
	 * This command was removed in LTTng 2.9.
	 */
	return -LTTNG_ERR_UND;
}

/*
 * Set default channel attributes.
 * If either or both of the arguments are null, attr content is zeroe'd.
 */
void lttng_channel_set_default_attr(struct lttng_domain *domain,
		struct lttng_channel_attr *attr)
{
	struct lttng_channel_extended *extended;

	/* Safety check */
	if (attr == NULL || domain == NULL) {
		return;
	}

	extended = (struct lttng_channel_extended *) attr->extended.ptr;
	memset(attr, 0, sizeof(struct lttng_channel_attr));

	/* Same for all domains. */
	attr->overwrite = DEFAULT_CHANNEL_OVERWRITE;
	attr->tracefile_size = DEFAULT_CHANNEL_TRACEFILE_SIZE;
	attr->tracefile_count = DEFAULT_CHANNEL_TRACEFILE_COUNT;

	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
		attr->switch_timer_interval =
				DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER;
		attr->read_timer_interval = DEFAULT_KERNEL_CHANNEL_READ_TIMER;
		attr->subbuf_size = default_get_kernel_channel_subbuf_size();
		attr->num_subbuf = DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM;
		attr->output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		if (extended) {
			extended->monitor_timer_interval =
					DEFAULT_KERNEL_CHANNEL_MONITOR_TIMER;
			extended->blocking_timeout =
					DEFAULT_KERNEL_CHANNEL_BLOCKING_TIMEOUT;
		}
		break;
	case LTTNG_DOMAIN_UST:
		switch (domain->buf_type) {
		case LTTNG_BUFFER_PER_UID:
			attr->subbuf_size = default_get_ust_uid_channel_subbuf_size();
			attr->num_subbuf = DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM;
			attr->output = DEFAULT_UST_UID_CHANNEL_OUTPUT;
			attr->switch_timer_interval =
					DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER;
			attr->read_timer_interval =
					DEFAULT_UST_UID_CHANNEL_READ_TIMER;
			if (extended) {
				extended->monitor_timer_interval =
						DEFAULT_UST_UID_CHANNEL_MONITOR_TIMER;
				extended->blocking_timeout =
						DEFAULT_UST_UID_CHANNEL_BLOCKING_TIMEOUT;
			}
			break;
		case LTTNG_BUFFER_PER_PID:
		default:
			attr->subbuf_size = default_get_ust_pid_channel_subbuf_size();
			attr->num_subbuf = DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM;
			attr->output = DEFAULT_UST_PID_CHANNEL_OUTPUT;
			attr->switch_timer_interval =
					DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER;
			attr->read_timer_interval =
					DEFAULT_UST_PID_CHANNEL_READ_TIMER;
			if (extended) {
				extended->monitor_timer_interval =
						DEFAULT_UST_PID_CHANNEL_MONITOR_TIMER;
				extended->blocking_timeout =
						DEFAULT_UST_PID_CHANNEL_BLOCKING_TIMEOUT;
			}
			break;
		}
	default:
		/* Default behavior: leave set to 0. */
		break;
	}

	attr->extended.ptr = extended;
}

int lttng_channel_get_discarded_event_count(struct lttng_channel *channel,
		uint64_t *discarded_events)
{
	int ret = 0;
	struct lttng_channel_extended *chan_ext;

	if (!channel || !discarded_events) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	chan_ext = channel->attr.extended.ptr;
	if (!chan_ext) {
		/*
		 * This can happen since the lttng_channel structure is
		 * used for other tasks where this pointer is never set.
		 */
		*discarded_events = 0;
		goto end;
	}

	*discarded_events = chan_ext->discarded_events;
end:
	return ret;
}

int lttng_channel_get_lost_packet_count(struct lttng_channel *channel,
		uint64_t *lost_packets)
{
	int ret = 0;
	struct lttng_channel_extended *chan_ext;

	if (!channel || !lost_packets) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	chan_ext = channel->attr.extended.ptr;
	if (!chan_ext) {
		/*
		 * This can happen since the lttng_channel structure is
		 * used for other tasks where this pointer is never set.
		 */
		*lost_packets = 0;
		goto end;
	}

	*lost_packets = chan_ext->lost_packets;
end:
	return ret;
}

int lttng_channel_get_monitor_timer_interval(struct lttng_channel *chan,
		uint64_t *monitor_timer_interval)
{
	int ret = 0;

	if (!chan || !monitor_timer_interval) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!chan->attr.extended.ptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	*monitor_timer_interval = ((struct lttng_channel_extended *)
			chan->attr.extended.ptr)->monitor_timer_interval;
end:
	return ret;
}

int lttng_channel_set_monitor_timer_interval(struct lttng_channel *chan,
		uint64_t monitor_timer_interval)
{
	int ret = 0;

	if (!chan || !chan->attr.extended.ptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	((struct lttng_channel_extended *)
			chan->attr.extended.ptr)->monitor_timer_interval =
			monitor_timer_interval;
end:
	return ret;
}

int lttng_channel_get_blocking_timeout(struct lttng_channel *chan,
		int64_t *blocking_timeout)
{
	int ret = 0;

	if (!chan || !blocking_timeout) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!chan->attr.extended.ptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	*blocking_timeout = ((struct lttng_channel_extended *)
			chan->attr.extended.ptr)->blocking_timeout;
end:
	return ret;
}

int lttng_channel_set_blocking_timeout(struct lttng_channel *chan,
		int64_t blocking_timeout)
{
	int ret = 0;
	int64_t msec_timeout;

	if (!chan || !chan->attr.extended.ptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (blocking_timeout < 0 && blocking_timeout != -1) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/*
	 * LTTng-ust's use of poll() to implement this timeout mechanism forces
	 * us to accept a narrower range of values (msecs expressed as a signed
	 * 32-bit integer).
	 */
	msec_timeout = blocking_timeout / 1000;
	if (msec_timeout != (int32_t) msec_timeout) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	((struct lttng_channel_extended *)
			chan->attr.extended.ptr)->blocking_timeout =
			blocking_timeout;
end:
	return ret;
}

/*
 * Check if session daemon is alive.
 *
 * Return 1 if alive or 0 if not.
 * On error returns a negative value.
 */
int lttng_session_daemon_alive(void)
{
	int ret;

	ret = set_session_daemon_path();
	if (ret < 0) {
		/* Error. */
		return ret;
	}

	if (*sessiond_sock_path == '\0') {
		/*
		 * No socket path set. Weird error which means the constructor
		 * was not called.
		 */
		assert(0);
	}

	ret = try_connect_sessiond(sessiond_sock_path);
	if (ret < 0) {
		/* Not alive. */
		return 0;
	}

	/* Is alive. */
	return 1;
}

/*
 * Set URL for a consumer for a session and domain.
 *
 * Return 0 on success, else a negative value.
 */
int lttng_set_consumer_url(struct lttng_handle *handle,
		const char *control_url, const char *data_url)
{
	int ret;
	ssize_t size;
	struct lttcomm_session_msg lsm;
	struct lttng_uri *uris = NULL;

	if (handle == NULL || (control_url == NULL && data_url == NULL)) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_SET_CONSUMER_URI;

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	size = uri_parse_str_urls(control_url, data_url, &uris);
	if (size < 0) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.u.uri.size = size;

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, uris,
			sizeof(struct lttng_uri) * size, NULL);

	free(uris);
	return ret;
}

/*
 * [OBSOLETE]
 */
int lttng_enable_consumer(struct lttng_handle *handle)
{
	return -ENOSYS;
}

/*
 * [OBSOLETE]
 */
int lttng_disable_consumer(struct lttng_handle *handle)
{
	return -ENOSYS;
}

/*
 * This is an extension of create session that is ONLY and SHOULD only be used
 * by the lttng command line program. It exists to avoid using URI parsing in
 * the lttng client.
 *
 * We need the date and time for the trace path subdirectory for the case where
 * the user does NOT define one using either -o or -U. Using the normal
 * lttng_create_session API call, we have no clue on the session daemon side if
 * the URL was generated automatically by the client or define by the user.
 *
 * So this function "wrapper" is hidden from the public API, takes the datetime
 * string and appends it if necessary to the URI subdirectory before sending it
 * to the session daemon.
 *
 * With this extra function, the lttng_create_session call behavior is not
 * changed and the timestamp is appended to the URI on the session daemon side
 * if necessary.
 */
int _lttng_create_session_ext(const char *name, const char *url,
		const char *datetime)
{
	int ret;
	ssize_t size;
	struct lttcomm_session_msg lsm;
	struct lttng_uri *uris = NULL;

	if (name == NULL || datetime == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_CREATE_SESSION;
	lttng_ctl_copy_string(lsm.session.name, name, sizeof(lsm.session.name));

	/* There should never be a data URL. */
	size = uri_parse_str_urls(url, NULL, &uris);
	if (size < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	lsm.u.uri.size = size;

	if (size > 0 && uris[0].dtype != LTTNG_DST_PATH && strlen(uris[0].subdir) == 0) {
		/* Don't append datetime if the name was automatically created. */
		if (strncmp(name, DEFAULT_SESSION_NAME "-",
					strlen(DEFAULT_SESSION_NAME) + 1)) {
			ret = snprintf(uris[0].subdir, sizeof(uris[0].subdir), "%s-%s",
					name, datetime);
		} else {
			ret = snprintf(uris[0].subdir, sizeof(uris[0].subdir), "%s", name);
		}
		if (ret < 0) {
			PERROR("snprintf uri subdir");
			ret = -LTTNG_ERR_FATAL;
			goto error;
		}
	}

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, uris,
			sizeof(struct lttng_uri) * size, NULL);

error:
	free(uris);
	return ret;
}

/*
 * For a given session name, this call checks if the data is ready to be read
 * or is still being extracted by the consumer(s) hence not ready to be used by
 * any readers.
 */
int lttng_data_pending(const char *session_name)
{
	int ret;
	struct lttcomm_session_msg lsm;
	uint8_t *pending = NULL;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_DATA_PENDING;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &pending);
	if (ret < 0) {
		goto end;
	} else if (ret != 1) {
		/* Unexpected payload size */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = (int) *pending;
end:
	free(pending);
	return ret;
}

/*
 * Create a session exclusively used for snapshot.
 *
 * Returns LTTNG_OK on success or a negative error code.
 */
int lttng_create_session_snapshot(const char *name, const char *snapshot_url)
{
	int ret;
	ssize_t size;
	struct lttcomm_session_msg lsm;
	struct lttng_uri *uris = NULL;

	if (name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_CREATE_SESSION_SNAPSHOT;
	lttng_ctl_copy_string(lsm.session.name, name, sizeof(lsm.session.name));

	size = uri_parse_str_urls(snapshot_url, NULL, &uris);
	if (size < 0) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.u.uri.size = size;

	/*
	 * If the user does not specify a custom subdir, use the session name.
	 */
	if (size > 0 && uris[0].dtype != LTTNG_DST_PATH && strlen(uris[0].subdir) == 0) {
		ret = snprintf(uris[0].subdir, sizeof(uris[0].subdir), "%s", name);
		if (ret < 0) {
			PERROR("snprintf uri subdir");
			ret = -LTTNG_ERR_FATAL;
			goto error;
		}
	}

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, uris,
			sizeof(struct lttng_uri) * size, NULL);

error:
	free(uris);
	return ret;
}

/*
 * Create a session exclusively used for live.
 *
 * Returns LTTNG_OK on success or a negative error code.
 */
int lttng_create_session_live(const char *name, const char *url,
		unsigned int timer_interval)
{
	int ret;
	ssize_t size;
	struct lttcomm_session_msg lsm;
	struct lttng_uri *uris = NULL;

	if (name == NULL || timer_interval == 0) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_CREATE_SESSION_LIVE;
	lttng_ctl_copy_string(lsm.session.name, name, sizeof(lsm.session.name));

	if (url) {
		size = uri_parse_str_urls(url, NULL, &uris);
		if (size <= 0) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		/* file:// is not accepted for live session. */
		if (uris[0].dtype == LTTNG_DST_PATH) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
	} else {
		size = 0;
	}

	lsm.u.session_live.nb_uri = size;
	lsm.u.session_live.timer_interval = timer_interval;

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, uris,
			sizeof(struct lttng_uri) * size, NULL);

end:
	free(uris);
	return ret;
}

/*
 * List PIDs in the tracker.
 *
 * enabled is set to whether the PID tracker is enabled.
 * pids is set to an allocated array of PIDs currently tracked. On
 * success, pids must be freed by the caller.
 * nr_pids is set to the number of entries contained by the pids array.
 *
 * Returns 0 on success, else a negative LTTng error code.
 */
int lttng_list_tracker_pids(struct lttng_handle *handle,
		int *_enabled, int32_t **_pids, size_t *_nr_pids)
{
	int ret;
	int enabled = 1;
	struct lttcomm_session_msg lsm;
	size_t nr_pids;
	int32_t *pids;

	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_LIST_TRACKER_PIDS;
	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &pids);
	if (ret < 0) {
		return ret;
	}
	nr_pids = ret / sizeof(int32_t);
	if (nr_pids == 1 && pids[0] == -1) {
		free(pids);
		pids = NULL;
		enabled = 0;
		nr_pids = 0;
	}
	*_enabled = enabled;
	*_pids = pids;
	*_nr_pids = nr_pids;
	return 0;
}

/*
 * Regenerate the metadata for a session.
 * Return 0 on success, a negative error code on error.
 */
int lttng_regenerate_metadata(const char *session_name)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (!session_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_REGENERATE_METADATA;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, NULL);
	if (ret < 0) {
		goto end;
	}

	ret = 0;
end:
	return ret;
}

/*
 * Deprecated, replaced by lttng_regenerate_metadata.
 */
int lttng_metadata_regenerate(const char *session_name)
{
	return lttng_regenerate_metadata(session_name);
}

/*
 * Regenerate the statedump of a session.
 * Return 0 on success, a negative error code on error.
 */
int lttng_regenerate_statedump(const char *session_name)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (!session_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_REGENERATE_STATEDUMP;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, NULL);
	if (ret < 0) {
		goto end;
	}

	ret = 0;
end:
	return ret;
}

int lttng_register_trigger(struct lttng_trigger *trigger)
{
	int ret;
	struct lttcomm_session_msg lsm;
	char *trigger_buf = NULL;
	ssize_t trigger_size;

	if (!trigger) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!lttng_trigger_validate(trigger)) {
		ret = -LTTNG_ERR_INVALID_TRIGGER;
		goto end;
	}

	trigger_size = lttng_trigger_serialize(trigger, NULL);
	if (trigger_size < 0) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	trigger_buf = zmalloc(trigger_size);
	if (!trigger_buf) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_REGISTER_TRIGGER;
	if (lttng_trigger_serialize(trigger, trigger_buf) < 0) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	lsm.u.trigger.length = (uint32_t) trigger_size;
	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, trigger_buf,
			trigger_size, NULL);
end:
	free(trigger_buf);
	return ret;
}

int lttng_unregister_trigger(struct lttng_trigger *trigger)
{
	int ret;
	struct lttcomm_session_msg lsm;
	char *trigger_buf = NULL;
	ssize_t trigger_size;

	if (!trigger) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!lttng_trigger_validate(trigger)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	trigger_size = lttng_trigger_serialize(trigger, NULL);
	if (trigger_size < 0) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	trigger_buf = zmalloc(trigger_size);
	if (!trigger_buf) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_UNREGISTER_TRIGGER;
	if (lttng_trigger_serialize(trigger, trigger_buf) < 0) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	lsm.u.trigger.length = (uint32_t) trigger_size;
	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, trigger_buf,
			trigger_size, NULL);
end:
	free(trigger_buf);
	return ret;
}

/*
 * lib constructor.
 */
static void __attribute__((constructor)) init(void)
{
	/* Set default session group */
	lttng_set_tracing_group(DEFAULT_TRACING_GROUP);
}

/*
 * lib destructor.
 */
static void __attribute__((destructor)) lttng_ctl_exit(void)
{
	free(tracing_group);
}
