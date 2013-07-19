/*
 * liblttngctl.c
 *
 * Linux Trace Toolkit Control Library
 *
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
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

#define _GNU_SOURCE
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
static char health_sock_path[PATH_MAX];

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
static int send_session_varlen(void *data, size_t len)
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
 *  Check if we are in the specified group.
 *
 *  If yes return 1, else return -1.
 */
static int check_tracing_group(const char *grp_name)
{
	struct group *grp_tracing;	/* no free(). See getgrnam(3) */
	gid_t *grp_list;
	int grp_list_size, grp_id, i;
	int ret = -1;

	/* Get GID of group 'tracing' */
	grp_tracing = getgrnam(grp_name);
	if (!grp_tracing) {
		/* If grp_tracing is NULL, the group does not exist. */
		goto end;
	}

	/* Get number of supplementary group IDs */
	grp_list_size = getgroups(0, NULL);
	if (grp_list_size < 0) {
		perror("getgroups");
		goto end;
	}

	/* Alloc group list of the right size */
	grp_list = malloc(grp_list_size * sizeof(gid_t));
	if (!grp_list) {
		perror("malloc");
		goto end;
	}
	grp_id = getgroups(grp_list_size, grp_list);
	if (grp_id < 0) {
		perror("getgroups");
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
		/* Not alive */
		goto error;
	}

	ret = lttcomm_close_unix_sock(ret);
	if (ret < 0) {
		perror("lttcomm_close_unix_sock");
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
	int in_tgroup = 0;	/* In tracing group */
	uid_t uid;

	uid = getuid();

	if (uid != 0) {
		/* Are we in the tracing group ? */
		in_tgroup = check_tracing_group(tracing_group);
	}

	if ((uid == 0) || in_tgroup) {
		lttng_ctl_copy_string(sessiond_sock_path,
				DEFAULT_GLOBAL_CLIENT_UNIX_SOCK, sizeof(sessiond_sock_path));
	}

	if (uid != 0) {
		int ret;

		if (in_tgroup) {
			/* Tracing group */
			ret = try_connect_sessiond(sessiond_sock_path);
			if (ret >= 0) {
				goto end;
			}
			/* Global session daemon not available... */
		}
		/* ...or not in tracing group (and not root), default */

		/*
		 * With GNU C <  2.1, snprintf returns -1 if the target buffer is too small;
		 * With GNU C >= 2.1, snprintf returns the required size (excluding closing null)
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
 *  Connect to the LTTng session daemon.
 *
 *  On success, return 0. On error, return -1.
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

	/* Connect to the sesssion daemon */
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

/*
 * Ask the session daemon a specific command and put the data into buf.
 * Takes extra var. len. data as input to send to the session daemon.
 *
 * Return size of data (only payload, not header) or a negative error code.
 */
LTTNG_HIDDEN
int lttng_ctl_ask_sessiond_varlen(struct lttcomm_session_msg *lsm,
		void *vardata, size_t varlen, void **buf)
{
	int ret;
	size_t size;
	void *data = NULL;
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
	ret = send_session_varlen(vardata, varlen);
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

	size = llm.data_size;
	if (size == 0) {
		/* If client free with size 0 */
		if (buf != NULL) {
			*buf = NULL;
		}
		ret = 0;
		goto end;
	}

	data = (void*) malloc(size);

	/* Get payload data */
	ret = recv_data_sessiond(data, size);
	if (ret < 0) {
		free(data);
		goto end;
	}

	/*
	 * Extra protection not to dereference a NULL pointer. If buf is NULL at
	 * this point, an error is returned and data is freed.
	 */
	if (buf == NULL) {
		ret = -LTTNG_ERR_INVALID;
		free(data);
		goto end;
	}

	*buf = data;
	ret = size;

end:
	disconnect_sessiond();
	return ret;
}

/*
 * Create lttng handle and return pointer.
 * The returned pointer will be NULL in case of malloc() error.
 */
struct lttng_handle *lttng_create_handle(const char *session_name,
		struct lttng_domain *domain)
{
	struct lttng_handle *handle = NULL;

	if (domain == NULL) {
		goto end;
	}

	handle = malloc(sizeof(struct lttng_handle));
	if (handle == NULL) {
		PERROR("malloc handle");
		goto end;
	}

	/* Copy session name */
	lttng_ctl_copy_string(handle->session_name, session_name,
			sizeof(handle->session_name));

	/* Copy lttng domain */
	lttng_ctl_copy_lttng_domain(&handle->domain, domain);

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
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_register_consumer(struct lttng_handle *handle,
		const char *socket_path)
{
	struct lttcomm_session_msg lsm;

	if (handle == NULL || socket_path == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTNG_REGISTER_CONSUMER;
	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	lttng_ctl_copy_string(lsm.u.reg.path, socket_path, sizeof(lsm.u.reg.path));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 *  Start tracing for all traces of the session.
 *  Returns size of returned session payload data or a negative error code.
 */
int lttng_start_tracing(const char *session_name)
{
	struct lttcomm_session_msg lsm;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

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

	_MSG("Waiting for data availability");
	fflush(stdout);

	/* Check for data availability */
	do {
		data_ret = lttng_data_pending(session_name);
		if (data_ret < 0) {
			/* Return the data available call error. */
			ret = data_ret;
			goto error;
		}

		/*
		 * Data sleep time before retrying (in usec). Don't sleep if the call
		 * returned value indicates availability.
		 */
		if (data_ret) {
			usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME);
			_MSG(".");
			fflush(stdout);
		}
	} while (data_ret != 0);

	MSG("");

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
	struct lttcomm_session_msg lsm;

	/* Safety check. Both are mandatory */
	if (handle == NULL || ctx == NULL) {
		return -LTTNG_ERR_INVALID;
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

	memcpy(&lsm.u.context.ctx, ctx, sizeof(struct lttng_event_context));

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 *  Enable event(s) for a channel.
 *  If no event name is specified, all events are enabled.
 *  If no channel name is specified, the default 'channel0' is used.
 *  Returns size of returned session payload data or a negative error code.
 */
int lttng_enable_event(struct lttng_handle *handle,
		struct lttng_event *ev, const char *channel_name)
{
	struct lttcomm_session_msg lsm;

	if (handle == NULL || ev == NULL) {
		return -LTTNG_ERR_INVALID;
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

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	if (ev->name[0] != '\0') {
		lsm.cmd_type = LTTNG_ENABLE_EVENT;
	} else {
		lsm.cmd_type = LTTNG_ENABLE_ALL_EVENT;
	}
	memcpy(&lsm.u.enable.event, ev, sizeof(lsm.u.enable.event));

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
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
	struct lttcomm_session_msg lsm;
	struct filter_parser_ctx *ctx;
	FILE *fmem;
	int ret = 0;

	if (!filter_expression) {
		/*
		 * Fall back to normal event enabling if no filter
		 * specified.
		 */
		return lttng_enable_event(handle, event, channel_name);
	}

	/*
	 * Empty filter string will always be rejected by the parser
	 * anyway, so treat this corner-case early to eliminate
	 * lttng_fmemopen error for 0-byte allocation.
	 */
	if (handle == NULL || filter_expression[0] == '\0') {
		return -LTTNG_ERR_INVALID;
	}

	/*
	 * casting const to non-const, as the underlying function will
	 * use it in read-only mode.
	 */
	fmem = lttng_fmemopen((void *) filter_expression,
			strlen(filter_expression), "r");
	if (!fmem) {
		fprintf(stderr, "Error opening memory as stream\n");
		return -LTTNG_ERR_FILTER_NOMEM;
	}
	ctx = filter_parser_ctx_alloc(fmem);
	if (!ctx) {
		fprintf(stderr, "Error allocating parser\n");
		ret = -LTTNG_ERR_FILTER_NOMEM;
		goto alloc_error;
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

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTNG_ENABLE_EVENT_WITH_FILTER;

	/* If no channel name, send empty string. */
	if (channel_name == NULL) {
		lttng_ctl_copy_string(lsm.u.enable.channel_name, "",
				sizeof(lsm.u.enable.channel_name));
	} else {
		lttng_ctl_copy_string(lsm.u.enable.channel_name, channel_name,
				sizeof(lsm.u.enable.channel_name));
	}

	/* Copy event name */
	if (event) {
		memcpy(&lsm.u.enable.event, event, sizeof(lsm.u.enable.event));
	}

	lsm.u.enable.bytecode_len = sizeof(ctx->bytecode->b)
			+ bytecode_get_len(&ctx->bytecode->b);

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond_varlen(&lsm, &ctx->bytecode->b,
				lsm.u.enable.bytecode_len, NULL);

	filter_bytecode_free(ctx);
	filter_ir_free(ctx);
	filter_parser_ctx_free(ctx);
	if (fclose(fmem) != 0) {
		perror("fclose");
	}
	return ret;

parse_error:
	filter_bytecode_free(ctx);
	filter_ir_free(ctx);
	filter_parser_ctx_free(ctx);
alloc_error:
	if (fclose(fmem) != 0) {
		perror("fclose");
	}
	return ret;
}

/*
 *  Disable event(s) of a channel and domain.
 *  If no event name is specified, all events are disabled.
 *  If no channel name is specified, the default 'channel0' is used.
 *  Returns size of returned session payload data or a negative error code.
 */
int lttng_disable_event(struct lttng_handle *handle, const char *name,
		const char *channel_name)
{
	struct lttcomm_session_msg lsm;

	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
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

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	if (name != NULL) {
		lttng_ctl_copy_string(lsm.u.disable.name, name,
				sizeof(lsm.u.disable.name));
		lsm.cmd_type = LTTNG_DISABLE_EVENT;
	} else {
		lsm.cmd_type = LTTNG_DISABLE_ALL_EVENT;
	}

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 *  Enable channel per domain
 *  Returns size of returned session payload data or a negative error code.
 */
int lttng_enable_channel(struct lttng_handle *handle,
		struct lttng_channel *chan)
{
	struct lttcomm_session_msg lsm;

	/*
	 * NULL arguments are forbidden. No default values.
	 */
	if (handle == NULL || chan == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	memcpy(&lsm.u.channel.chan, chan, sizeof(lsm.u.channel.chan));

	lsm.cmd_type = LTTNG_ENABLE_CHANNEL;

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 *  All tracing will be stopped for registered events of the channel.
 *  Returns size of returned session payload data or a negative error code.
 */
int lttng_disable_channel(struct lttng_handle *handle, const char *name)
{
	struct lttcomm_session_msg lsm;

	/* Safety check. Both are mandatory */
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
 *  Lists all available tracepoints of domain.
 *  Sets the contents of the events array.
 *  Returns the number of lttng_event entries in events;
 *  on error, returns a negative value.
 */
int lttng_list_tracepoints(struct lttng_handle *handle,
		struct lttng_event **events)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTNG_LIST_TRACEPOINTS;
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) events);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_event);
}

/*
 *  Lists all available tracepoint fields of domain.
 *  Sets the contents of the event field array.
 *  Returns the number of lttng_event_field entries in events;
 *  on error, returns a negative value.
 */
int lttng_list_tracepoint_fields(struct lttng_handle *handle,
		struct lttng_event_field **fields)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTNG_LIST_TRACEPOINT_FIELDS;
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) fields);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_event_field);
}

/*
 *  Returns a human readable string describing
 *  the error code (a negative value).
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

	ret = lttng_ctl_ask_sessiond_varlen(&lsm, uris,
			sizeof(struct lttng_uri) * size, NULL);

	free(uris);
	return ret;
}

/*
 *  Destroy session using name.
 *  Returns size of returned session payload data or a negative error code.
 */
int lttng_destroy_session(const char *session_name)
{
	struct lttcomm_session_msg lsm;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTNG_DESTROY_SESSION;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 *  Ask the session daemon for all available sessions.
 *  Sets the contents of the sessions array.
 *  Returns the number of lttng_session entries in sessions;
 *  on error, returns a negative value.
 */
int lttng_list_sessions(struct lttng_session **sessions)
{
	int ret;
	struct lttcomm_session_msg lsm;

	lsm.cmd_type = LTTNG_LIST_SESSIONS;
	ret = lttng_ctl_ask_sessiond(&lsm, (void**) sessions);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_session);
}

/*
 *  Ask the session daemon for all available domains of a session.
 *  Sets the contents of the domains array.
 *  Returns the number of lttng_domain entries in domains;
 *  on error, returns a negative value.
 */
int lttng_list_domains(const char *session_name,
		struct lttng_domain **domains)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

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
 *  Ask the session daemon for all available channels of a session.
 *  Sets the contents of the channels array.
 *  Returns the number of lttng_channel entries in channels;
 *  on error, returns a negative value.
 */
int lttng_list_channels(struct lttng_handle *handle,
		struct lttng_channel **channels)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (handle == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTNG_LIST_CHANNELS;
	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond(&lsm, (void**) channels);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_channel);
}

/*
 *  Ask the session daemon for all available events of a session channel.
 *  Sets the contents of the events array.
 *  Returns the number of lttng_event entries in events;
 *  on error, returns a negative value.
 */
int lttng_list_events(struct lttng_handle *handle,
		const char *channel_name, struct lttng_event **events)
{
	int ret;
	struct lttcomm_session_msg lsm;

	/* Safety check. An handle and channel name are mandatory */
	if (handle == NULL || channel_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTNG_LIST_EVENTS;
	lttng_ctl_copy_string(lsm.session.name, handle->session_name,
			sizeof(lsm.session.name));
	lttng_ctl_copy_string(lsm.u.list.channel_name, channel_name,
			sizeof(lsm.u.list.channel_name));

	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	ret = lttng_ctl_ask_sessiond(&lsm, (void**) events);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_event);
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

/*
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_calibrate(struct lttng_handle *handle,
		struct lttng_calibrate *calibrate)
{
	struct lttcomm_session_msg lsm;

	/* Safety check. NULL pointer are forbidden */
	if (handle == NULL || calibrate == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTNG_CALIBRATE;
	lttng_ctl_copy_lttng_domain(&lsm.domain, &handle->domain);

	memcpy(&lsm.u.calibrate, calibrate, sizeof(lsm.u.calibrate));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Set default channel attributes.
 * If either or both of the arguments are null, attr content is zeroe'd.
 */
void lttng_channel_set_default_attr(struct lttng_domain *domain,
		struct lttng_channel_attr *attr)
{
	/* Safety check */
	if (attr == NULL || domain == NULL) {
		return;
	}

	memset(attr, 0, sizeof(struct lttng_channel_attr));

	/* Same for all domains. */
	attr->overwrite = DEFAULT_CHANNEL_OVERWRITE;
	attr->tracefile_size = DEFAULT_CHANNEL_TRACEFILE_SIZE;
	attr->tracefile_count = DEFAULT_CHANNEL_TRACEFILE_COUNT;

	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
		attr->switch_timer_interval = DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER;
		attr->read_timer_interval = DEFAULT_KERNEL_CHANNEL_READ_TIMER;
		attr->subbuf_size = default_get_kernel_channel_subbuf_size();
		attr->num_subbuf = DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM;
		attr->output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		break;
	case LTTNG_DOMAIN_UST:
		switch (domain->buf_type) {
		case LTTNG_BUFFER_PER_UID:
			attr->subbuf_size = default_get_ust_uid_channel_subbuf_size();
			attr->num_subbuf = DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM;
			attr->output = DEFAULT_UST_UID_CHANNEL_OUTPUT;
			attr->switch_timer_interval = DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER;
			attr->read_timer_interval = DEFAULT_UST_UID_CHANNEL_READ_TIMER;
			break;
		case LTTNG_BUFFER_PER_PID:
		default:
			attr->subbuf_size = default_get_ust_pid_channel_subbuf_size();
			attr->num_subbuf = DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM;
			attr->output = DEFAULT_UST_PID_CHANNEL_OUTPUT;
			attr->switch_timer_interval = DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER;
			attr->read_timer_interval = DEFAULT_UST_PID_CHANNEL_READ_TIMER;
			break;
		}
	default:
		/* Default behavior: leave set to 0. */
		break;
	}
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
		/* Error */
		return ret;
	}

	if (*sessiond_sock_path == '\0') {
		/*
		 * No socket path set. Weird error which means the constructor was not
		 * called.
		 */
		assert(0);
	}

	ret = try_connect_sessiond(sessiond_sock_path);
	if (ret < 0) {
		/* Not alive */
		return 0;
	}

	/* Is alive */
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

	ret = lttng_ctl_ask_sessiond_varlen(&lsm, uris,
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
 * Set health socket path by putting it in the global health_sock_path
 * variable.
 *
 * Returns 0 on success or assert(0) on ENOMEM.
 */
static int set_health_socket_path(void)
{
	int in_tgroup = 0;	/* In tracing group */
	uid_t uid;
	const char *home;

	uid = getuid();

	if (uid != 0) {
		/* Are we in the tracing group ? */
		in_tgroup = check_tracing_group(tracing_group);
	}

	if ((uid == 0) || in_tgroup) {
		lttng_ctl_copy_string(health_sock_path,
				DEFAULT_GLOBAL_HEALTH_UNIX_SOCK, sizeof(health_sock_path));
	}

	if (uid != 0) {
		int ret;

		/*
		 * With GNU C <  2.1, snprintf returns -1 if the target buffer is too small;
		 * With GNU C >= 2.1, snprintf returns the required size (excluding closing null)
		 */
		home = utils_get_home_dir();
		if (home == NULL) {
			/* Fallback in /tmp .. */
			home = "/tmp";
		}

		ret = snprintf(health_sock_path, sizeof(health_sock_path),
				DEFAULT_HOME_HEALTH_UNIX_SOCK, home);
		if ((ret < 0) || (ret >= sizeof(health_sock_path))) {
			/* ENOMEM at this point... just kill the control lib. */
			assert(0);
		}
	}

	return 0;
}

/*
 * Check session daemon health for a specific health component.
 *
 * Return 0 if health is OK or else 1 if BAD.
 *
 * Any other negative value is a lttng error code which can be translated with
 * lttng_strerror().
 */
int lttng_health_check(enum lttng_health_component c)
{
	int sock, ret;
	struct lttcomm_health_msg msg;
	struct lttcomm_health_data reply;

	/* Connect to the sesssion daemon */
	sock = lttcomm_connect_unix_sock(health_sock_path);
	if (sock < 0) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto error;
	}

	msg.cmd = LTTNG_HEALTH_CHECK;
	msg.component = c;

	ret = lttcomm_send_unix_sock(sock, (void *)&msg, sizeof(msg));
	if (ret < 0) {
		ret = -LTTNG_ERR_FATAL;
		goto close_error;
	}

	ret = lttcomm_recv_unix_sock(sock, (void *)&reply, sizeof(reply));
	if (ret < 0) {
		ret = -LTTNG_ERR_FATAL;
		goto close_error;
	}

	ret = reply.ret_code;

close_error:
	{
		int closeret;

		closeret = close(sock);
		assert(!closeret);
	}

error:
	return ret;
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

	/* There should never be a data URL */
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

	ret = lttng_ctl_ask_sessiond_varlen(&lsm, uris,
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

	if (session_name == NULL) {
		return -LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTNG_DATA_PENDING;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, NULL);

	/*
	 * The lttng_ctl_ask_sessiond function negate the return code if it's not
	 * LTTNG_OK so getting -1 means that the reply ret_code was 1 thus meaning
	 * that the data is available. Yes it is hackish but for now this is the
	 * only way.
	 */
	if (ret == -1) {
		ret = 1;
	}

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

	ret = lttng_ctl_ask_sessiond_varlen(&lsm, uris,
			sizeof(struct lttng_uri) * size, NULL);

	free(uris);
	return ret;
}

/*
 * lib constructor
 */
static void __attribute__((constructor)) init()
{
	/* Set default session group */
	lttng_set_tracing_group(DEFAULT_TRACING_GROUP);
	/* Set socket for health check */
	(void) set_health_socket_path();
}

/*
 * lib destructor
 */
static void __attribute__((destructor)) lttng_ctl_exit()
{
	free(tracing_group);
}
