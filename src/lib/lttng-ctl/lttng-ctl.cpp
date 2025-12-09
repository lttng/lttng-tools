/*
 * lttng-ctl.c
 *
 * Linux Trace Toolkit Control Library
 *
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "event-rule-convert.hpp"
#include "lttng-ctl-helper.hpp"

#include <common/align.hpp>
#include <common/bytecode/bytecode.hpp>
#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/compat/getenv.hpp>
#include <common/compat/string.hpp>
#include <common/defaults.hpp>
#include <common/dynamic-array.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/exception.hpp>
#include <common/filter/filter-ast.hpp>
/* NOLINTNEXTLINE */
#include <common/filter/filter-parser.hpp>
#include <common/filter/memstream.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <common/scope-exit.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/tracker.hpp>
#include <common/unix.hpp>
#include <common/uri.hpp>
#include <common/utils.hpp>

#include <lttng/channel-internal.hpp>
#include <lttng/destruction-handle.h>
#include <lttng/endpoint.h>
#include <lttng/error-query-internal.hpp>
#include <lttng/event-internal.hpp>
#include <lttng/health-internal.hpp>
#include <lttng/lttng-error.h>
#include <lttng/lttng.h>
#include <lttng/session-descriptor-internal.hpp>
#include <lttng/session-internal.hpp>
#include <lttng/trigger/trigger-internal.hpp>
#include <lttng/userspace-probe-internal.hpp>

#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define COPY_DOMAIN_PACKED(dst, src)                               \
	do {                                                       \
		struct lttng_domain _tmp_domain;                   \
                                                                   \
		lttng_ctl_copy_lttng_domain(&_tmp_domain, &(src)); \
		(dst) = _tmp_domain;                               \
	} while (0)

/* Socket to session daemon for communication */
static int sessiond_socket = -1;
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
LTTNG_EXPORT int lttng_opt_quiet;
LTTNG_EXPORT int lttng_opt_verbose;
LTTNG_EXPORT int lttng_opt_mi;

/*
 * Copy domain to lttcomm_session_msg domain.
 *
 * If domain is unknown, default domain will be the kernel.
 */
void lttng_ctl_copy_lttng_domain(struct lttng_domain *dst, struct lttng_domain *src)
{
	if (src && dst) {
		switch (src->type) {
		case LTTNG_DOMAIN_KERNEL:
		case LTTNG_DOMAIN_UST:
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_LOG4J2:
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

	DBG("LSM cmd type: '%s' (%d)",
	    lttcomm_sessiond_command_str((lttcomm_sessiond_command) lsm->cmd_type),
	    lsm->cmd_type);

	ret = lttcomm_send_creds_unix_sock(
		sessiond_socket, lsm, sizeof(struct lttcomm_session_msg));
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
 * Send file descriptors to the session daemon.
 *
 * On success, returns the number of bytes sent (>=0)
 * On error, returns -1
 */
static int send_session_fds(const int *fds, size_t nb_fd)
{
	int ret;

	if (!connected) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto end;
	}

	if (!fds || !nb_fd) {
		ret = 0;
		goto end;
	}

	ret = lttcomm_send_fds_unix_sock(sessiond_socket, fds, nb_fd);
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
 * On error, returns a negative lttng_error_code.
 */
static int recv_data_sessiond(void *buf, size_t len)
{
	int ret;

	LTTNG_ASSERT(len > 0);

	if (!connected) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto end;
	}

	ret = lttcomm_recv_unix_sock(sessiond_socket, buf, len);
	if (ret < 0) {
		ret = -LTTNG_ERR_FATAL;
	} else if (ret == 0) {
		ret = -LTTNG_ERR_NO_SESSIOND;
	}

end:
	return ret;
}

/*
 * Receive a payload from the session daemon by appending to an existing
 * payload.
 * On success, returns the number of bytes received (>=0)
 * On error, returns a negative lttng_error_code.
 */
static int recv_payload_sessiond(struct lttng_payload *payload, size_t len)
{
	int ret;
	const size_t original_payload_size = payload->buffer.size;

	ret = lttng_dynamic_buffer_set_size(&payload->buffer, payload->buffer.size + len);
	if (ret) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	ret = recv_data_sessiond(payload->buffer.data + original_payload_size, len);
end:
	return ret;
}

/*
 * Check if we are in the specified group.
 *
 * If yes return true, else false.
 */
bool lttng_check_in_tracing_group()
{
	gid_t *grp_list, tracing_gid;
	int grp_list_size, grp_id, i;
	bool in_tracing_group = false;
	const char *grp_name = tracing_group;

	/* Get GID of group 'tracing' */
	if (utils_get_group_id(grp_name, false, &tracing_gid)) {
		/* If grp_tracing is NULL, the group does not exist. */
		goto end;
	}

	/* Get number of supplementary group IDs */
	grp_list_size = getgroups(0, nullptr);
	if (grp_list_size < 0) {
		PERROR("getgroups");
		goto end;
	}

	/* Alloc group list of the right size */
	grp_list = calloc<gid_t>(grp_list_size);
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
		if (grp_list[i] == tracing_gid) {
			in_tracing_group = true;
			break;
		}
	}

free_list:
	free(grp_list);

end:
	return in_tracing_group;
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
static int set_session_daemon_path()
{
	bool in_tracing_group = false;
	uid_t uid;

	uid = getuid();

	if (uid != 0) {
		/* Are we in the tracing group ? */
		in_tracing_group = lttng_check_in_tracing_group();
	}

	auto rundir = lttng::make_unique_wrapper<char, lttng::memory::free>();
	if ((uid == 0) || in_tracing_group == 1) {
		int ret = -1;

		rundir.reset(utils_get_rundir(in_tracing_group));
		if (!rundir) {
			goto error;
		}
		ret = snprintf(sessiond_sock_path,
			       sizeof(sessiond_sock_path),
			       DEFAULT_CLIENT_UNIX_SOCK,
			       rundir.get());
		if ((ret < 0) || (ret >= sizeof(sessiond_sock_path))) {
			goto error;
		}
	}

	if (uid != 0) {
		int ret;

		rundir.reset(utils_get_rundir(0));
		if (!rundir) {
			goto error;
		}

		if (in_tracing_group) {
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
		ret = snprintf(sessiond_sock_path,
			       sizeof(sessiond_sock_path),
			       DEFAULT_CLIENT_UNIX_SOCK,
			       rundir.get());
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
 * On success, return the socket's file descriptor. On error, return -1.
 */
int connect_sessiond()
{
	int ret;

	ret = set_session_daemon_path();
	if (ret < 0) {
		goto error;
	}

	/* Connect to the sesssion daemon. */
	ret = lttcomm_connect_unix_sock(sessiond_sock_path);
	if (ret < 0) {
		goto error;
	}

	return ret;

error:
	return -1;
}

static void reset_global_sessiond_connection_state()
{
	sessiond_socket = -1;
	connected = 0;
}

/*
 *  Clean disconnect from the session daemon.
 *
 *  On success, return 0. On error, return -1.
 */
static int disconnect_sessiond()
{
	int ret = 0;

	if (connected) {
		ret = lttcomm_close_unix_sock(sessiond_socket);
		reset_global_sessiond_connection_state();
	}

	return ret;
}

static int recv_sessiond_optional_data(size_t len, void **user_buf, size_t *user_len)
{
	int ret = 0;
	char *buf = nullptr;

	if (len) {
		if (!user_len) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		buf = zmalloc<char>(len);
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
		buf = nullptr;
		*user_len = len;
	} else {
		/* No command header. */
		if (user_len) {
			*user_len = 0;
		}

		if (user_buf) {
			*user_buf = nullptr;
		}
	}

end:
	free(buf);
	return ret;
}

/*
 * Ask the session daemon a specific command and put the data into buf.
 * Takes extra var. len. data and file descriptors as input to send to the
 * session daemon.
 *
 * Return size of data (only payload, not header) or a negative error code.
 */
int lttng_ctl_ask_sessiond_fds_varlen(struct lttcomm_session_msg *lsm,
				      const int *fds,
				      size_t nb_fd,
				      const void *vardata,
				      size_t vardata_len,
				      void **user_payload_buf,
				      void **user_cmd_header_buf,
				      size_t *user_cmd_header_len)
{
	int ret;
	size_t payload_len;
	struct lttcomm_lttng_msg llm;

	ret = connect_sessiond();
	if (ret < 0) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto end;
	} else {
		sessiond_socket = ret;
		connected = 1;
	}

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

	/* Send fds */
	ret = send_session_fds(fds, nb_fd);
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
	ret = recv_sessiond_optional_data(
		llm.cmd_header_size, user_cmd_header_buf, user_cmd_header_len);
	if (ret < 0) {
		goto end;
	}

	/* Get payload from data transmission */
	ret = recv_sessiond_optional_data(llm.data_size, user_payload_buf, &payload_len);
	if (ret < 0) {
		goto end;
	}

	ret = llm.data_size;

end:
	disconnect_sessiond();
	return ret;
}

int lttng_ctl_ask_sessiond_payload(struct lttng_payload_view *message, struct lttng_payload *reply)
{
	int ret;
	struct lttcomm_lttng_msg llm;
	const int fd_count = lttng_payload_view_get_fd_handle_count(message);

	LTTNG_ASSERT(reply->buffer.size == 0);
	LTTNG_ASSERT(lttng_dynamic_pointer_array_get_count(&reply->_fd_handles) == 0);

	ret = connect_sessiond();
	if (ret < 0) {
		ret = -LTTNG_ERR_NO_SESSIOND;
		goto end;
	} else {
		sessiond_socket = ret;
		connected = 1;
	}

	/* Send command to session daemon */
	ret = lttcomm_send_creds_unix_sock(
		sessiond_socket, message->buffer.data, message->buffer.size);
	if (ret < 0) {
		ret = -LTTNG_ERR_FATAL;
		goto end;
	}

	if (fd_count > 0) {
		ret = lttcomm_send_payload_view_fds_unix_sock(sessiond_socket, message);
		if (ret < 0) {
			ret = -LTTNG_ERR_FATAL;
			goto end;
		}
	}

	/* Get header from data transmission */
	ret = recv_payload_sessiond(reply, sizeof(llm));
	if (ret < 0) {
		/* Ret value is a valid lttng error code. */
		goto end;
	}

	llm = *((typeof(llm) *) reply->buffer.data);

	/* Check error code if OK */
	if (llm.ret_code != LTTNG_OK) {
		if (llm.ret_code < LTTNG_OK || llm.ret_code >= LTTNG_ERR_NR) {
			/* Invalid error code received. */
			ret = -LTTNG_ERR_UNK;
		} else {
			ret = -llm.ret_code;
		}
		goto end;
	}

	if (llm.cmd_header_size > 0) {
		ret = recv_payload_sessiond(reply, llm.cmd_header_size);
		if (ret < 0) {
			goto end;
		}
	}

	/* Get command header from data transmission */
	if (llm.data_size > 0) {
		ret = recv_payload_sessiond(reply, llm.data_size);
		if (ret < 0) {
			goto end;
		}
	}

	if (llm.fd_count > 0) {
		ret = lttcomm_recv_payload_fds_unix_sock(sessiond_socket, llm.fd_count, reply);
		if (ret < 0) {
			goto end;
		}
	}

	/* Don't return the llm header to the caller. */
	memmove(reply->buffer.data,
		reply->buffer.data + sizeof(llm),
		reply->buffer.size - sizeof(llm));
	ret = lttng_dynamic_buffer_set_size(&reply->buffer, reply->buffer.size - sizeof(llm));
	if (ret) {
		/* Can't happen as size is reduced. */
		abort();
	}

	ret = reply->buffer.size;

end:
	disconnect_sessiond();
	return ret;
}

/*
 * Create lttng handle and return pointer.
 *
 * The returned pointer will be NULL in case of malloc() error.
 */
struct lttng_handle *lttng_create_handle(const char *session_name, struct lttng_domain *domain)
{
	int ret;
	struct lttng_handle *handle = nullptr;

	handle = zmalloc<lttng_handle>();
	if (handle == nullptr) {
		PERROR("malloc handle");
		goto end;
	}

	/* Copy session name */
	ret = lttng_strncpy(handle->session_name, session_name ?: "", sizeof(handle->session_name));
	if (ret) {
		goto error;
	}

	/* Copy lttng domain or leave initialized to 0. */
	if (domain) {
		lttng_ctl_copy_lttng_domain(&handle->domain, domain);
	}

end:
	return handle;
error:
	free(handle);
	return nullptr;
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
int lttng_register_consumer(struct lttng_handle *handle, const char *socket_path)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (handle == nullptr || socket_path == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_REGISTER_CONSUMER;
	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	ret = lttng_strncpy(lsm.u.reg.path, socket_path, sizeof(lsm.u.reg.path));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, nullptr);
end:
	return ret;
}

/*
 * Start tracing for all traces of the session.
 *
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_start_tracing(const char *session_name)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (session_name == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_START_TRACE;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, nullptr);
end:
	return ret;
}

/*
 * Stop tracing for all traces of the session.
 */
static int _lttng_stop_tracing(const char *session_name, int wait)
{
	int ret, data_ret;
	struct lttcomm_session_msg lsm;

	if (session_name == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_STOP_TRACE;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, nullptr);
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
			usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME_US);
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
		      struct lttng_event_context *ctx,
		      const char *event_name __attribute__((unused)),
		      const char *channel_name)
{
	int ret;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_ADD_CONTEXT,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	/* Safety check. Both are mandatory. */
	if (handle == nullptr || ctx == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_dynamic_buffer_set_size(&payload.buffer, sizeof(lsm));
	if (ret) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* If no channel name, send empty string. */
	ret = lttng_strncpy(
		lsm.u.context.channel_name, channel_name ?: "", sizeof(lsm.u.context.channel_name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);
	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_event_context_serialize(ctx, &payload);
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lsm.u.context.length = payload.buffer.size - sizeof(lsm);

	/* Update message header. */
	memcpy(payload.buffer.data, &lsm, sizeof(lsm));

	{
		struct lttng_payload reply;
		struct lttng_payload_view payload_view =
			lttng_payload_view_from_payload(&payload, 0, -1);

		lttng_payload_init(&reply);
		ret = lttng_ctl_ask_sessiond_payload(&payload_view, &reply);
		lttng_payload_reset(&reply);
		if (ret) {
			goto end;
		}
	}

end:
	lttng_payload_reset(&payload);
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
		       struct lttng_event *ev,
		       const char *channel_name)
{
	return lttng_enable_event_with_exclusions(handle, ev, channel_name, nullptr, 0, nullptr);
}

/*
 * Create or enable an event with a filter expression.
 *
 * Return negative error value on error.
 * Return size of returned session payload data if OK.
 */
int lttng_enable_event_with_filter(struct lttng_handle *handle,
				   struct lttng_event *event,
				   const char *channel_name,
				   const char *filter_expression)
{
	return lttng_enable_event_with_exclusions(
		handle, event, channel_name, filter_expression, 0, nullptr);
}

/*
 * Depending on the event, return a new agent filter expression or
 * an empty string if not applicable.
 *
 * An event with NO loglevel and the name is * will return an empty string.
 */
static std::string build_agent_filter_expression(const char *original_filter_expression,
						 const lttng_event& ev,
						 const lttng_domain& domain)
{
	std::string agent_filter;

	try {
		/* Don't add filter for the '*' event. */
		std::string logger_name_filter;

		if (lttng::c_string_view(ev.name) != "*" &&
		    lttng::c_string_view(ev.name).len() != 0) {
			logger_name_filter = fmt::format("logger_name == \"{}\"", ev.name);
		}

		if (original_filter_expression == nullptr) {
			agent_filter = std::move(logger_name_filter);
		} else {
			if (logger_name_filter.size() > 0) {
				agent_filter = fmt::format("({}) && ({})",
							   original_filter_expression,
							   logger_name_filter);
			} else {
				agent_filter.append(original_filter_expression);
			}
		}

		/* Add loglevel filtering if any for the agent domains. */
		if (ev.loglevel_type != LTTNG_EVENT_LOGLEVEL_ALL) {
			std::string op;

			if (ev.loglevel_type == LTTNG_EVENT_LOGLEVEL_RANGE) {
				/*
				 * Log4j2 is the only agent domain for which more severe logging
				 * levels have a lower numerical value.
				 */
				if (domain.type == LTTNG_DOMAIN_LOG4J2) {
					op = "<=";
				} else {
					op = ">=";
				}
			} else {
				op = "==";
			}

			if (original_filter_expression != nullptr || !agent_filter.empty()) {
				std::string existing_filter = !agent_filter.empty() ?
					agent_filter :
					std::string(original_filter_expression);

				agent_filter = fmt::format("({}) && (int_loglevel {} {})",
							   existing_filter,
							   op,
							   ev.loglevel);
			} else {
				agent_filter = fmt::format("int_loglevel {} {}", op, ev.loglevel);
			}
		}
	} catch (const std::exception& e) {
		return std::string();
	}

	return agent_filter;
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
				       struct lttng_event *ev,
				       const char *channel_name,
				       const char *original_filter_expression,
				       int exclusion_count,
				       char **exclusion_list)
{
	lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_ENABLE_EVENT,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	lttng_payload payload;
	int ret = 0;

	if (handle == nullptr || ev == nullptr) {
		return -LTTNG_ERR_INVALID;
	}

	/*
	 * Empty filter string will always be rejected by the parser
	 * anyway, so treat this corner-case early to eliminate
	 * lttng_fmemopen error for 0-byte allocation.
	 */
	if (original_filter_expression && strlen(original_filter_expression) == 0) {
		return -LTTNG_ERR_INVALID;
	}

	if (ev->type == LTTNG_EVENT_ALL) {
		/*
		 * Since we modify the user's parameter, ensure it is set back to its original value
		 * on exit.
		 */
		const auto restore_event_type_value =
			lttng::make_scope_exit([&ev]() noexcept { ev->type = LTTNG_EVENT_ALL; });

		ev->type = LTTNG_EVENT_TRACEPOINT;
		const auto tp_ret = lttng_enable_event_with_exclusions(handle,
								       ev,
								       channel_name,
								       original_filter_expression,
								       exclusion_count,
								       exclusion_list);
		if (tp_ret < 0 || handle->domain.type != LTTNG_DOMAIN_KERNEL) {
			return tp_ret;
		}

		ev->type = LTTNG_EVENT_SYSCALL;
		const auto syscall_ret =
			lttng_enable_event_with_exclusions(handle,
							   ev,
							   channel_name,
							   original_filter_expression,
							   exclusion_count,
							   exclusion_list);
		return syscall_ret;
	}

	/*
	 * We have either a filter or some exclusions, so we need to set up
	 * a variable-length payload from where to send the data.
	 */
	lttng_payload_init(&payload);
	/* Clean-up payload when returning. */
	auto cleanup_payload =
		lttng::make_scope_exit([&payload]() noexcept { lttng_payload_reset(&payload); });

	/* The filter expression may be modified below in the case of agent domains. */
	std::string filter_expression(original_filter_expression ?: "");

	if (ev->name[0] == '\0') {
		/* Enable all events. */
		ret = lttng_strncpy(ev->name, "*", sizeof(ev->name));
		LTTNG_ASSERT(ret == 0);
	}

	if (handle->domain.type == LTTNG_DOMAIN_JUL || handle->domain.type == LTTNG_DOMAIN_LOG4J ||
	    handle->domain.type == LTTNG_DOMAIN_LOG4J2 ||
	    handle->domain.type == LTTNG_DOMAIN_PYTHON) {
		/* Setup agent filter if needed. */
		try {
			filter_expression = build_agent_filter_expression(
				original_filter_expression, *ev, handle->domain);
		} catch (const std::bad_alloc& bad_alloc_ex) {
			return -LTTNG_ERR_NOMEM;
		} catch (...) {
			return -LTTNG_ERR_UNK;
		}
	}

	if (handle->domain.type == LTTNG_DOMAIN_KERNEL && ev->type == LTTNG_EVENT_ALL) {
		/*
		 * Syscall and tracepoints are different instrumentation types that must be
		 * enabled by separate event rules.
		 */
		ev->type = LTTNG_EVENT_SYSCALL;
		ret = lttng_enable_event_with_exclusions(handle,
							 ev,
							 channel_name,
							 original_filter_expression,
							 exclusion_count,
							 exclusion_list);
		if (ret < 0) {
			return ret;
		}

		ev->type = LTTNG_EVENT_TRACEPOINT;
		ret = lttng_enable_event_with_exclusions(handle,
							 ev,
							 channel_name,
							 original_filter_expression,
							 exclusion_count,
							 exclusion_list);
		if (ret < 0) {
			return ret;
		}

		return ret;
	}

	std::vector<lttng::c_string_view> exclusions_vec;
	if (exclusion_count > 0) {
		exclusions_vec.reserve(exclusion_count);

		for (unsigned int i = 0; i < exclusion_count; i++) {
			exclusions_vec.emplace_back(exclusion_list[i]);
		}
	}

	lttng::event_rule_uptr event_rule;
	try {
		event_rule = lttng::ctl::create_event_rule_from_lttng_event(
			*ev,
			handle->domain.type,
			original_filter_expression ?
				nonstd::make_optional(original_filter_expression) :
				nonstd::nullopt,
			exclusions_vec);
	} catch (const lttng::ctl::error& ctl_error) {
		DBG("%s", ctl_error.what());
		return -LTTNG_ERR_INVALID;
	} catch (const std::exception& ex) {
		DBG("%s", ex.what());
		return -LTTNG_ERR_UNK;
	}

	filter_parser_ctx *ctx = nullptr;

	if (filter_expression.size() > 0) {
		ret = filter_parser_ctx_create_from_filter_expression(filter_expression.c_str(),
								      &ctx);
		if (ret) {
			return -LTTNG_ERR_INVALID;
		}
	}

	const auto free_bytecode_ir_and_parser_context = lttng::make_scope_exit([ctx]() noexcept {
		if (!ctx) {
			return;
		}

		filter_bytecode_free(ctx);
		filter_ir_free(ctx);
		filter_parser_ctx_free(ctx);
	});

	const auto bytecode_len =
		ctx ? (bytecode_get_len(&ctx->bytecode->b) + sizeof(ctx->bytecode->b)) : 0;
	if (bytecode_len > LTTNG_FILTER_MAX_LEN) {
		return -LTTNG_ERR_INVALID;
	}

	ret = lttng_event_serialize(ev,
				    exclusion_count,
				    exclusion_list,
				    filter_expression.size() > 0 ? filter_expression.c_str() :
								   nullptr,
				    bytecode_len,
				    (ctx && bytecode_len) ? &ctx->bytecode->b : nullptr,
				    &payload);
	if (ret) {
		return -LTTNG_ERR_INVALID;
	}

	if (!lttng_event_rule_validate(event_rule.get())) {
		return -LTTNG_ERR_INVALID;
	}

	ret = lttng_event_rule_serialize(event_rule.get(), &payload);
	if (ret) {
		return -LTTNG_ERR_INVALID;
	}

	/* If no channel name, send empty string. */
	ret = lttng_strncpy(
		lsm.u.enable.channel_name, channel_name ?: "", sizeof(lsm.u.enable.channel_name));
	if (ret) {
		return -LTTNG_ERR_INVALID;
	}

	/* Domain */
	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	/* Session name */
	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		return -LTTNG_ERR_INVALID;
	}

	/* Length of the serialized event rule. */
	lsm.u.enable.length = (uint32_t) payload.buffer.size;

	lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
	const auto fd_count = lttng_payload_view_get_fd_handle_count(&view);

	if (fd_count < 0) {
		return -LTTNG_ERR_UNK;
	}

	LTTNG_ASSERT(fd_count == 0 || fd_count == 2);

	std::vector<int> fds_to_send;

	fds_to_send.reserve(fd_count);
	for (auto i = 0; i < fd_count; i++) {
		fd_handle *h = lttng_payload_view_pop_fd_handle(&view);

		if (!h) {
			return -LTTNG_ERR_UNK;
		}

		const auto fd_to_send = fd_handle_get_fd(h);
		fds_to_send.push_back(fd_to_send);
		fd_handle_put(h);
	}

	lsm.fd_count = fd_count;

	return lttng_ctl_ask_sessiond_fds_varlen(&lsm,
						 fd_count ? fds_to_send.data() : nullptr,
						 fd_count,
						 view.buffer.size ? view.buffer.data : nullptr,
						 view.buffer.size,
						 nullptr,
						 nullptr,
						 nullptr);
}

int lttng_disable_event_ext(struct lttng_handle *handle,
			    struct lttng_event *ev,
			    const char *channel_name,
			    const char *original_filter_expression)
{
	lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_DISABLE_EVENT,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	lttng_payload payload;
	int ret = 0;

	if (handle == nullptr || ev == nullptr) {
		return -LTTNG_ERR_INVALID;
	}

	/*
	 * Empty filter string will always be rejected by the parser
	 * anyway, so treat this corner-case early to eliminate
	 * lttng_fmemopen error for 0-byte allocation.
	 */
	if (original_filter_expression && strlen(original_filter_expression) == 0) {
		return -LTTNG_ERR_INVALID;
	}

	/*
	 * We have either a filter or some exclusions, so we need to set up
	 * a variable-length payload from where to send the data.
	 */
	lttng_payload_init(&payload);
	/* Clean-up payload when returning. */
	auto cleanup_payload =
		lttng::make_scope_exit([&payload]() noexcept { lttng_payload_reset(&payload); });

	/* The filter expression may be modified below in the case of agent domains. */
	std::string filter_expression(original_filter_expression ?: "");

	if (handle->domain.type == LTTNG_DOMAIN_JUL || handle->domain.type == LTTNG_DOMAIN_LOG4J ||
	    handle->domain.type == LTTNG_DOMAIN_LOG4J2 ||
	    handle->domain.type == LTTNG_DOMAIN_PYTHON) {
		/* Setup agent filter if needed. */
		try {
			filter_expression = build_agent_filter_expression(
				original_filter_expression, *ev, handle->domain);
		} catch (const std::bad_alloc& bad_alloc_ex) {
			return -LTTNG_ERR_NOMEM;
		} catch (...) {
			return -LTTNG_ERR_UNK;
		}
	}

	const std::vector<lttng::c_string_view> exclusions_vec;
	lttng::event_rule_uptr event_rule;
	if (ev->type != LTTNG_EVENT_ALL) {
		try {
			event_rule = lttng::ctl::create_event_rule_from_lttng_event(
				*ev,
				handle->domain.type,
				original_filter_expression ?
					nonstd::make_optional(original_filter_expression) :
					nonstd::nullopt,
				exclusions_vec);
		} catch (const lttng::ctl::error& ctl_error) {
			DBG("%s", ctl_error.what());
			return -LTTNG_ERR_INVALID;
		} catch (const std::exception& ex) {
			DBG("%s", ex.what());
			return -LTTNG_ERR_UNK;
		}
	}

	filter_parser_ctx *ctx = nullptr;
	if (filter_expression.size() > 0) {
		ret = filter_parser_ctx_create_from_filter_expression(filter_expression.c_str(),
								      &ctx);
		if (ret) {
			return -LTTNG_ERR_INVALID;
		}
	}

	const auto free_bytecode_ir_and_parser_context = lttng::make_scope_exit([ctx]() noexcept {
		if (!ctx) {
			return;
		}

		filter_bytecode_free(ctx);
		filter_ir_free(ctx);
		filter_parser_ctx_free(ctx);
	});

	const auto bytecode_len =
		ctx ? (bytecode_get_len(&ctx->bytecode->b) + sizeof(ctx->bytecode->b)) : 0;
	if (bytecode_len > LTTNG_FILTER_MAX_LEN) {
		return -LTTNG_ERR_INVALID;
	}

	ret = lttng_event_serialize(ev,
				    0,
				    nullptr,
				    filter_expression.size() > 0 ? filter_expression.c_str() :
								   nullptr,
				    bytecode_len,
				    (ctx && bytecode_len) ? &ctx->bytecode->b : nullptr,
				    &payload);
	if (ret) {
		return -LTTNG_ERR_INVALID;
	}

	if (event_rule) {
		ret = lttng_event_rule_serialize(event_rule.get(), &payload);
		if (ret) {
			return -LTTNG_ERR_INVALID;
		}
	}

	/* If no channel name, send empty string. */
	ret = lttng_strncpy(
		lsm.u.disable.channel_name, channel_name ?: "", sizeof(lsm.u.disable.channel_name));
	if (ret) {
		return -LTTNG_ERR_INVALID;
	}

	/* Domain */
	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	/* Session name */
	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		return -LTTNG_ERR_INVALID;
	}

	/* Length of the serialized event rule. */
	lsm.u.disable.length = (uint32_t) payload.buffer.size;

	lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
	const auto fd_count = lttng_payload_view_get_fd_handle_count(&view);

	if (fd_count < 0) {
		return -LTTNG_ERR_UNK;
	}

	LTTNG_ASSERT(fd_count == 0 || fd_count == 2);

	std::vector<int> fds_to_send;

	fds_to_send.reserve(fd_count);
	for (auto i = 0; i < fd_count; i++) {
		fd_handle *h = lttng_payload_view_pop_fd_handle(&view);

		if (!h) {
			return -LTTNG_ERR_UNK;
		}

		const auto fd_to_send = fd_handle_get_fd(h);
		fds_to_send.push_back(fd_to_send);
		fd_handle_put(h);
	}

	lsm.fd_count = fd_count;

	return lttng_ctl_ask_sessiond_fds_varlen(&lsm,
						 fd_count ? fds_to_send.data() : nullptr,
						 fd_count,
						 view.buffer.size ? view.buffer.data : nullptr,
						 view.buffer.size,
						 nullptr,
						 nullptr,
						 nullptr);
}

/*
 * Disable event(s) of a channel and domain.
 * If no event name is specified, all events are disabled.
 * If no channel name is specified, the default 'channel0' is used.
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_disable_event(struct lttng_handle *handle, const char *name, const char *channel_name)
{
	int ret;
	struct lttng_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.loglevel = -1;
	ev.type = LTTNG_EVENT_ALL;
	ret = lttng_strncpy(ev.name, name ?: "", sizeof(ev.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_disable_event_ext(handle, &ev, channel_name, nullptr);
end:
	return ret;
}

struct lttng_channel *lttng_channel_create(struct lttng_domain *domain)
{
	struct lttng_channel *channel = nullptr;

	if (!domain) {
		goto end;
	}

	/* Validate domain. */
	switch (domain->type) {
	case LTTNG_DOMAIN_UST:
		switch (domain->buf_type) {
		case LTTNG_BUFFER_PER_UID:
		case LTTNG_BUFFER_PER_PID:
			break;
		default:
			goto end;
		}
		break;
	case LTTNG_DOMAIN_KERNEL:
		if (domain->buf_type != LTTNG_BUFFER_GLOBAL) {
			goto end;
		}
		break;
	default:
		goto end;
	}

	channel = lttng_channel_create_internal();
	if (!channel) {
		goto end;
	}

	lttng_channel_set_default_attr(domain, &channel->attr);
end:
	return channel;
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
int lttng_enable_channel(struct lttng_handle *handle, struct lttng_channel *in_chan)
{
	int ret;
	struct lttng_dynamic_buffer buffer;
	struct lttcomm_session_msg lsm;
	struct lttng_channel *channel = nullptr;

	lttng_dynamic_buffer_init(&buffer);

	/* NULL arguments are forbidden. No default values. */
	if (handle == nullptr || in_chan == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/* Copy the channel for easier manipulation. */
	channel = lttng_channel_copy(in_chan);
	if (!channel) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Populate the channel extended attribute if necessary. */
	if (!channel->attr.extended.ptr) {
		struct lttng_channel_extended *extended = zmalloc<lttng_channel_extended>();

		if (!extended) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		lttng_channel_set_default_extended_attr(&handle->domain, extended);
		channel->attr.extended.ptr = extended;
	}

	/* Prepare the payload */
	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_ENABLE_CHANNEL;
	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_channel_serialize(channel, &buffer);
	if (ret) {
		ret = -LTTNG_ERR_FATAL;
		goto end;
	}

	lsm.u.channel.length = buffer.size;

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(&lsm, buffer.data, buffer.size, nullptr);
end:
	lttng_channel_destroy(channel);
	lttng_dynamic_buffer_reset(&buffer);
	return ret;
}

/*
 * All tracing will be stopped for registered events of the channel.
 * Returns size of returned session payload data or a negative error code.
 */
int lttng_disable_channel(struct lttng_handle *handle, const char *name)
{
	int ret;
	struct lttcomm_session_msg lsm;

	/* Safety check. Both are mandatory. */
	if (handle == nullptr || name == nullptr) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_DISABLE_CHANNEL;

	ret = lttng_strncpy(lsm.u.disable.channel_name, name, sizeof(lsm.u.disable.channel_name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, nullptr);
end:
	return ret;
}

/*
 * Lists all available tracepoints of domain.
 * Sets the contents of the events array.
 * Returns the number of lttng_event entries in events;
 * on error, returns a negative value.
 */
int lttng_list_tracepoints(struct lttng_handle *handle, struct lttng_event **events)
{
	enum lttng_error_code ret_code;
	int ret, total_payload_received;
	char *reception_buffer = nullptr;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINTS,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	struct lttcomm_list_command_header *cmd_header = nullptr;
	size_t cmd_header_len;
	unsigned int nb_events = 0;

	if (handle == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	ret = lttng_ctl_ask_sessiond_fds_varlen(&lsm,
						nullptr,
						0,
						nullptr,
						0,
						(void **) &reception_buffer,
						(void **) &cmd_header,
						&cmd_header_len);
	if (ret < 0) {
		goto end;
	}

	total_payload_received = ret;

	if (!cmd_header) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	if (cmd_header->count > INT_MAX) {
		ret = -LTTNG_ERR_OVERFLOW;
		goto end;
	}

	nb_events = (unsigned int) cmd_header->count;

	{
		const lttng_buffer_view events_view =
			lttng_buffer_view_init(reception_buffer, 0, total_payload_received);
		struct lttng_payload_view events_payload_view =
			lttng_payload_view_from_buffer_view(&events_view, 0, -1);

		ret_code = lttng_events_create_and_flatten_from_payload(
			&events_payload_view, nb_events, events);
		if (ret_code != LTTNG_OK) {
			ret = -ret_code;
			goto end;
		}
	}

	ret = (int) nb_events;

end:
	free(cmd_header);
	free(reception_buffer);
	return ret;
}

/*
 * Lists all available tracepoint fields of domain.
 * Sets the contents of the event field array.
 * Returns the number of lttng_event_field entries in events;
 * on error, returns a negative value.
 */
int lttng_list_tracepoint_fields(struct lttng_handle *handle, struct lttng_event_field **fields)
{
	enum lttng_error_code ret_code;
	int ret;
	struct lttcomm_session_msg lsm;
	const struct lttcomm_list_command_header *cmd_header = nullptr;
	unsigned int nb_event_fields = 0;
	struct lttng_payload reply;

	lttng_payload_init(&reply);

	if (handle == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINT_FIELDS;
	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	{
		lttng_payload_view message_view =
			lttng_payload_view_init_from_buffer((const char *) &lsm, 0, sizeof(lsm));

		ret = lttng_ctl_ask_sessiond_payload(&message_view, &reply);
		if (ret < 0) {
			goto end;
		}
	}

	{
		const lttng_buffer_view cmd_header_view = lttng_buffer_view_from_dynamic_buffer(
			&reply.buffer, 0, sizeof(*cmd_header));

		if (!lttng_buffer_view_is_valid(&cmd_header_view)) {
			ret = -LTTNG_ERR_INVALID_PROTOCOL;
			goto end;
		}

		cmd_header = (struct lttcomm_list_command_header *) cmd_header_view.data;
	}

	if (cmd_header->count > INT_MAX) {
		ret = -LTTNG_ERR_OVERFLOW;
		goto end;
	}

	nb_event_fields = cmd_header->count;

	{
		lttng_payload_view reply_view =
			lttng_payload_view_from_payload(&reply, sizeof(*cmd_header), -1);

		ret_code = lttng_event_fields_create_and_flatten_from_payload(
			&reply_view, nb_event_fields, fields);
		if (ret_code != LTTNG_OK) {
			ret = -ret_code;
			goto end;
		}
	}

	ret = nb_event_fields;

end:
	lttng_payload_reset(&reply);
	return ret;
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
	enum lttng_error_code ret_code;
	int ret, total_payload_received;
	char *reception_buffer = nullptr;
	struct lttcomm_session_msg lsm = {};
	struct lttcomm_list_command_header *cmd_header = nullptr;
	size_t cmd_header_len;
	uint32_t nb_events = 0;

	if (!events) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_SYSCALLS;
	/* Force kernel domain for system calls. */
	lsm.domain.type = LTTNG_DOMAIN_KERNEL;

	ret = lttng_ctl_ask_sessiond_fds_varlen(&lsm,
						nullptr,
						0,
						nullptr,
						0,
						(void **) &reception_buffer,
						(void **) &cmd_header,
						&cmd_header_len);
	if (ret < 0) {
		goto end;
	}
	total_payload_received = ret;

	if (!cmd_header) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	if (cmd_header->count > INT_MAX) {
		ret = -LTTNG_ERR_OVERFLOW;
		goto end;
	}

	nb_events = (unsigned int) cmd_header->count;

	{
		const struct lttng_buffer_view events_view =
			lttng_buffer_view_init(reception_buffer, 0, total_payload_received);
		struct lttng_payload_view events_payload_view =
			lttng_payload_view_from_buffer_view(&events_view, 0, -1);

		ret_code = lttng_events_create_and_flatten_from_payload(
			&events_payload_view, nb_events, events);
		if (ret_code != LTTNG_OK) {
			ret = -ret_code;
			goto end;
		}
	}

	ret = (int) nb_events;

end:
	free(reception_buffer);
	free(cmd_header);
	return ret;
}

/*
 * Returns a human readable string describing
 * the error code (positive or negative value).
 */
const char *lttng_strerror(int code)
{
	if (code > 0) {
		code = -code;
	}

	return error_get_str(code);
}

enum lttng_error_code lttng_create_session_ext(struct lttng_session_descriptor *session_descriptor)
{
	enum lttng_error_code ret_code;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_CREATE_SESSION_EXT,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	void *reply = nullptr;
	struct lttng_buffer_view reply_view;
	int reply_ret;
	bool sessiond_must_generate_ouput;
	struct lttng_dynamic_buffer payload;
	int ret;
	size_t descriptor_size;
	struct lttng_session_descriptor *descriptor_reply = nullptr;

	lttng_dynamic_buffer_init(&payload);
	if (!session_descriptor) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	sessiond_must_generate_ouput =
		!lttng_session_descriptor_is_output_destination_initialized(session_descriptor);
	if (sessiond_must_generate_ouput) {
		const char *home_dir = utils_get_home_dir();
		const size_t home_dir_len = home_dir ? strlen(home_dir) + 1 : 0;

		if (!home_dir || home_dir_len > LTTNG_PATH_MAX) {
			ret_code = LTTNG_ERR_FATAL;
			goto end;
		}

		lsm.u.create_session.home_dir_size = (uint16_t) home_dir_len;
		ret = lttng_dynamic_buffer_append(&payload, home_dir, home_dir_len);
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	descriptor_size = payload.size;
	ret = lttng_session_descriptor_serialize(session_descriptor, &payload);
	if (ret) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}
	descriptor_size = payload.size - descriptor_size;
	lsm.u.create_session.session_descriptor_size = descriptor_size;

	/* Command returns a session descriptor on success. */
	reply_ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(
		&lsm, payload.data, payload.size, &reply);
	if (reply_ret < 0) {
		ret_code = (lttng_error_code) -reply_ret;
		goto end;
	} else if (reply_ret == 0) {
		/* Socket unexpectedly closed by the session daemon. */
		ret_code = LTTNG_ERR_FATAL;
		goto end;
	}

	reply_view = lttng_buffer_view_init((const char *) reply, 0, reply_ret);
	ret = lttng_session_descriptor_create_from_buffer(&reply_view, &descriptor_reply);
	if (ret < 0) {
		ret_code = LTTNG_ERR_FATAL;
		goto end;
	}
	ret_code = LTTNG_OK;
	lttng_session_descriptor_assign(session_descriptor, descriptor_reply);
end:
	free(reply);
	lttng_dynamic_buffer_reset(&payload);
	lttng_session_descriptor_destroy(descriptor_reply);
	return ret_code;
}

/*
 * Create a new session using name and url for destination.
 *
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_create_session(const char *name, const char *url)
{
	int ret;
	ssize_t size;
	struct lttng_uri *uris = nullptr;
	struct lttng_session_descriptor *descriptor = nullptr;
	enum lttng_error_code ret_code;

	if (!name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	size = uri_parse_str_urls(url, nullptr, &uris);
	if (size < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	switch (size) {
	case 0:
		descriptor = lttng_session_descriptor_create(name);
		break;
	case 1:
		if (uris[0].dtype != LTTNG_DST_PATH) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		descriptor = lttng_session_descriptor_local_create(name, uris[0].dst.path);
		break;
	case 2:
		descriptor = lttng_session_descriptor_network_create(name, url, nullptr);
		break;
	default:
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	if (!descriptor) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	ret_code = lttng_create_session_ext(descriptor);
	ret = ret_code == LTTNG_OK ? 0 : -ret_code;
end:
	lttng_session_descriptor_destroy(descriptor);
	free(uris);
	return ret;
}

/*
 * Create a session exclusively used for snapshot.
 *
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_create_session_snapshot(const char *name, const char *snapshot_url)
{
	int ret;
	enum lttng_error_code ret_code;
	ssize_t size;
	struct lttng_uri *uris = nullptr;
	struct lttng_session_descriptor *descriptor = nullptr;

	if (!name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	size = uri_parse_str_urls(snapshot_url, nullptr, &uris);
	if (size < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	/*
	 * If the user does not specify a custom subdir, use the session name.
	 */
	if (size > 0 && uris[0].dtype != LTTNG_DST_PATH && strlen(uris[0].subdir) == 0) {
		ret = snprintf(uris[0].subdir, sizeof(uris[0].subdir), "%s", name);
		if (ret < 0) {
			PERROR("Failed to set session name as network destination sub-directory");
			ret = -LTTNG_ERR_FATAL;
			goto end;
		} else if (ret >= sizeof(uris[0].subdir)) {
			/* Truncated output. */
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
	}

	switch (size) {
	case 0:
		descriptor = lttng_session_descriptor_snapshot_create(name);
		break;
	case 1:
		if (uris[0].dtype != LTTNG_DST_PATH) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		descriptor = lttng_session_descriptor_snapshot_local_create(name, uris[0].dst.path);
		break;
	case 2:
		descriptor = lttng_session_descriptor_snapshot_network_create(
			name, snapshot_url, nullptr);
		break;
	default:
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	if (!descriptor) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	ret_code = lttng_create_session_ext(descriptor);
	ret = ret_code == LTTNG_OK ? 0 : -ret_code;
end:
	lttng_session_descriptor_destroy(descriptor);
	free(uris);
	return ret;
}

/*
 * Create a session exclusively used for live.
 *
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_create_session_live(const char *name, const char *url, unsigned int timer_interval)
{
	int ret;
	enum lttng_error_code ret_code;
	struct lttng_session_descriptor *descriptor = nullptr;

	if (!name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (url) {
		descriptor = lttng_session_descriptor_live_network_create(
			name, url, nullptr, timer_interval);
	} else {
		descriptor = lttng_session_descriptor_live_create(name, timer_interval);
	}
	if (!descriptor) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	ret_code = lttng_create_session_ext(descriptor);
	ret = ret_code == LTTNG_OK ? 0 : -ret_code;
end:
	lttng_session_descriptor_destroy(descriptor);
	return ret;
}

/*
 * Stop the session and wait for the data before destroying it
 *
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_destroy_session(const char *session_name)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_destruction_handle_status status;
	struct lttng_destruction_handle *handle = nullptr;

	/*
	 * Stop the tracing and wait for the data to be
	 * consumed.
	 */
	ret = _lttng_stop_tracing(session_name, 1);
	if (ret && ret != -LTTNG_ERR_TRACE_ALREADY_STOPPED) {
		goto end;
	}

	ret_code = lttng_destroy_session_ext(session_name, &handle);
	if (ret_code != LTTNG_OK) {
		ret = (int) -ret_code;
		goto end;
	}
	LTTNG_ASSERT(handle);

	/* Block until the completion of the destruction of the session. */
	status = lttng_destruction_handle_wait_for_completion(handle, -1);
	if (status != LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	status = lttng_destruction_handle_get_result(handle, &ret_code);
	if (status != LTTNG_DESTRUCTION_HANDLE_STATUS_OK) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}
	ret = ret_code == LTTNG_OK ? 0 : -ret_code;
end:
	lttng_destruction_handle_destroy(handle);
	return ret;
}

/*
 * Destroy the session without waiting for the data.
 */
int lttng_destroy_session_no_wait(const char *session_name)
{
	enum lttng_error_code ret_code;

	ret_code = lttng_destroy_session_ext(session_name, nullptr);
	return ret_code == LTTNG_OK ? 0 : -ret_code;
}

/*
 * Ask the session daemon for all available sessions.
 * Sets the contents of the sessions array.
 * Returns the number of lttng_session entries in sessions;
 * on error, returns a negative value.
 */
int lttng_list_sessions(struct lttng_session **out_sessions)
{
	int ret;
	struct lttcomm_session_msg lsm;
	const size_t session_size =
		sizeof(struct lttng_session) + sizeof(struct lttng_session_extended);
	size_t session_count, i;
	struct lttng_session_extended *sessions_extended_begin;
	struct lttng_session *sessions = nullptr;

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_SESSIONS;
	/*
	 * Initialize out_sessions to NULL so it is initialized when
	 * lttng_list_sessions returns 0, thus allowing *out_sessions to
	 * be subsequently freed.
	 */
	*out_sessions = nullptr;
	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &sessions);
	if (ret <= 0) {
		goto end;
	}
	if (!sessions) {
		ret = -LTTNG_ERR_FATAL;
		goto end;
	}

	if (ret % session_size) {
		ret = -LTTNG_ERR_UNK;
		free(sessions);
		goto end;
	}
	session_count = (size_t) ret / session_size;
	sessions_extended_begin = (struct lttng_session_extended *) (&sessions[session_count]);

	/* Set extended session info pointers. */
	for (i = 0; i < session_count; i++) {
		struct lttng_session *session = &sessions[i];
		struct lttng_session_extended *extended = &(sessions_extended_begin[i]);

		session->extended.ptr = extended;
	}

	ret = (int) session_count;
	*out_sessions = sessions;
end:
	return ret;
}

enum lttng_error_code lttng_session_get_creation_time(const struct lttng_session *session,
						      uint64_t *creation_time)
{
	enum lttng_error_code ret = LTTNG_OK;
	struct lttng_session_extended *extended;

	if (!session || !creation_time || !session->extended.ptr) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	extended = (lttng_session_extended *) session->extended.ptr;
	if (!extended->creation_time.is_set) {
		/* Not created on the session daemon yet. */
		ret = LTTNG_ERR_SESSION_NOT_EXIST;
		goto end;
	}
	*creation_time = extended->creation_time.value;
end:
	return ret;
}

enum lttng_get_session_shm_path_status
lttng_get_session_shm_path_override(const lttng_session *session, const char **shm_path)
{
	struct lttng_session_extended *extended;
	if (!session || !shm_path || !session->extended.ptr) {
		return LTTNG_GET_SESSION_SHM_PATH_STATUS_INVALID_PARAMETER;
	}

	extended = (lttng_session_extended *) session->extended.ptr;
	*shm_path = extended->shm_path.value;
	return strlen(*shm_path) == 0 ? LTTNG_GET_SESSION_SHM_PATH_STATUS_UNSET :
					LTTNG_GET_SESSION_SHM_PATH_STATUS_OK;
}

int lttng_set_session_shm_path(const char *session_name, const char *shm_path)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (session_name == nullptr) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_SET_SESSION_SHM_PATH;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_strncpy(
		lsm.u.set_shm_path.shm_path, shm_path ?: "", sizeof(lsm.u.set_shm_path.shm_path));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, nullptr);
end:
	return ret;
}

/*
 * Ask the session daemon for all available domains of a session.
 * Sets the contents of the domains array.
 * Returns the number of lttng_domain entries in domains;
 * on error, returns a negative value.
 */
int lttng_list_domains(const char *session_name, struct lttng_domain **domains)
{
	int ret;
	struct lttcomm_session_msg lsm;

	if (session_name == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_DOMAINS;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) domains);
	if (ret < 0) {
		goto error;
	}

	return ret / sizeof(struct lttng_domain);
error:
	return ret;
}

/*
 * Ask the session daemon for all available channels of a session.
 * Sets the contents of the channels array.
 * Returns the number of lttng_channel entries in channels;
 * on error, returns a negative value.
 */
int lttng_list_channels(struct lttng_handle *handle, struct lttng_channel **channels)
{
	int ret, total_payload_received;
	struct lttcomm_session_msg lsm;
	char *reception_buffer = nullptr;
	size_t cmd_header_len = 0;
	struct lttcomm_list_command_header *cmd_header = nullptr;
	struct lttng_dynamic_buffer tmp_buffer;

	lttng_dynamic_buffer_init(&tmp_buffer);

	if (handle == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_CHANNELS;
	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	ret = lttng_ctl_ask_sessiond_fds_varlen(&lsm,
						nullptr,
						0,
						nullptr,
						0,
						(void **) &reception_buffer,
						(void **) &cmd_header,
						&cmd_header_len);
	if (ret < 0) {
		goto end;
	}

	total_payload_received = ret;

	if (cmd_header_len != sizeof(*cmd_header)) {
		ret = -LTTNG_ERR_FATAL;
		goto end;
	}

	if (!cmd_header) {
		ret = LTTNG_ERR_UNK;
		goto end;
	}

	if (cmd_header->count > INT_MAX) {
		ret = -LTTNG_ERR_OVERFLOW;
		goto end;
	}

	{
		enum lttng_error_code ret_code;
		const struct lttng_buffer_view events_view =
			lttng_buffer_view_init(reception_buffer, 0, total_payload_received);

		ret_code = lttng_channels_create_and_flatten_from_buffer(
			&events_view, cmd_header->count, channels);
		if (ret_code != LTTNG_OK) {
			ret = -ret_code;
			goto end;
		}
	}

	ret = (int) cmd_header->count;
end:
	free(cmd_header);
	free(reception_buffer);
	return ret;
}

/*
 * Ask the session daemon for all available events of a session channel.
 * Sets the contents of the events array.
 * Returns the number of lttng_event entries in events;
 * on error, returns a negative value.
 */
int lttng_list_events(struct lttng_handle *handle,
		      const char *channel_name,
		      struct lttng_event **events)
{
	int ret;
	struct lttcomm_session_msg lsm = {};
	struct lttng_payload reply;
	struct lttng_payload_view lsm_view =
		lttng_payload_view_init_from_buffer((const char *) &lsm, 0, sizeof(lsm));
	unsigned int nb_events = 0;

	lttng_payload_init(&reply);

	/* Safety check. An handle and channel name are mandatory. */
	if (handle == nullptr || channel_name == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/* Initialize command parameters. */
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_EVENTS;
	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_strncpy(lsm.u.list.channel_name, channel_name, sizeof(lsm.u.list.channel_name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	/* Execute command against the session daemon. */
	ret = lttng_ctl_ask_sessiond_payload(&lsm_view, &reply);
	if (ret < 0) {
		goto end;
	}

	{
		const struct lttcomm_list_command_header *cmd_reply_header = nullptr;
		const lttng_payload_view cmd_reply_header_view =
			lttng_payload_view_from_payload(&reply, 0, sizeof(*cmd_reply_header));

		if (!lttng_payload_view_is_valid(&cmd_reply_header_view)) {
			ret = -LTTNG_ERR_INVALID_PROTOCOL;
			goto end;
		}

		cmd_reply_header = (const struct lttcomm_list_command_header *)
					   cmd_reply_header_view.buffer.data;
		if (cmd_reply_header->count > INT_MAX) {
			ret = -LTTNG_ERR_OVERFLOW;
			goto end;
		}

		nb_events = (unsigned int) cmd_reply_header->count;
	}

	{
		enum lttng_error_code ret_code;
		lttng_payload_view cmd_reply_payload = lttng_payload_view_from_payload(
			&reply, sizeof(struct lttcomm_list_command_header), -1);

		ret_code = lttng_events_create_and_flatten_from_payload(
			&cmd_reply_payload, nb_events, events);
		if (ret_code != LTTNG_OK) {
			ret = -((int) ret_code);
			goto end;
		}
	}

	ret = (int) nb_events;
end:
	lttng_payload_reset(&reply);
	return ret;
}

/*
 * Sets the tracing_group variable with name.
 * This function allocates memory pointed to by tracing_group.
 * On success, returns 0, on error, returns -1 (null name) or -ENOMEM.
 */
int lttng_set_tracing_group(const char *name)
{
	int ret = 0;
	char *new_group;

	if (name == nullptr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	new_group = strdup(name);
	if (!new_group) {
		ret = -LTTNG_ERR_FATAL;
		goto end;
	}

	free(tracing_group);
	tracing_group = new_group;
	new_group = nullptr;

end:
	return ret;
}

int lttng_calibrate(struct lttng_handle *handle __attribute__((unused)),
		    struct lttng_calibrate *calibrate __attribute__((unused)))
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
void lttng_channel_set_default_attr(struct lttng_domain *domain, struct lttng_channel_attr *attr)
{
	struct lttng_channel_extended *extended;

	/* Safety check */
	if (attr == nullptr || domain == nullptr) {
		return;
	}

	/* Save the pointer for later use */
	extended = (struct lttng_channel_extended *) attr->extended.ptr;
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

	if (extended) {
		lttng_channel_set_default_extended_attr(domain, extended);
	}

	/* Reassign the extended pointer. */
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

	chan_ext = (lttng_channel_extended *) channel->attr.extended.ptr;
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

int lttng_channel_get_lost_packet_count(struct lttng_channel *channel, uint64_t *lost_packets)
{
	int ret = 0;
	struct lttng_channel_extended *chan_ext;

	if (!channel || !lost_packets) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	chan_ext = (lttng_channel_extended *) channel->attr.extended.ptr;
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

int lttng_channel_get_monitor_timer_interval(const struct lttng_channel *chan,
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

	*monitor_timer_interval =
		((struct lttng_channel_extended *) chan->attr.extended.ptr)->monitor_timer_interval;
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

	((struct lttng_channel_extended *) chan->attr.extended.ptr)->monitor_timer_interval =
		monitor_timer_interval;
end:
	return ret;
}

int lttng_channel_get_blocking_timeout(const struct lttng_channel *chan, int64_t *blocking_timeout)
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

	*blocking_timeout =
		((struct lttng_channel_extended *) chan->attr.extended.ptr)->blocking_timeout;
end:
	return ret;
}

int lttng_channel_set_blocking_timeout(struct lttng_channel *chan, int64_t blocking_timeout)
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

	((struct lttng_channel_extended *) chan->attr.extended.ptr)->blocking_timeout =
		blocking_timeout;
end:
	return ret;
}

enum lttng_error_code
lttng_channel_get_allocation_policy(const struct lttng_channel *chan,
				    enum lttng_channel_allocation_policy *policy)
{
	if (!chan || !policy) {
		return LTTNG_ERR_INVALID;
	}

	const auto extended =
		static_cast<const struct lttng_channel_extended *>(chan->attr.extended.ptr);

	if (!extended) {
		return LTTNG_ERR_INVALID;
	}

	*policy = static_cast<enum lttng_channel_allocation_policy>(extended->allocation_policy);

	return LTTNG_OK;
}

enum lttng_error_code
lttng_channel_set_allocation_policy(struct lttng_channel *chan,
				    enum lttng_channel_allocation_policy policy)
{
	if (!chan) {
		return LTTNG_ERR_INVALID;
	}

	const auto extended = static_cast<struct lttng_channel_extended *>(chan->attr.extended.ptr);

	if (!extended) {
		return LTTNG_ERR_INVALID;
	}

	switch (policy) {
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU:
		/* Fallthrough */
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL:
		break;
	default:
		return LTTNG_ERR_INVALID;
	}

	extended->allocation_policy = static_cast<uint8_t>(policy);

	return LTTNG_OK;
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
		abort();
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
			   const char *control_url,
			   const char *data_url)
{
	int ret;
	ssize_t size;
	struct lttcomm_session_msg lsm;
	struct lttng_uri *uris = nullptr;

	if (handle == nullptr || (control_url == nullptr && data_url == nullptr)) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	memset(&lsm, 0, sizeof(lsm));

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_SET_CONSUMER_URI;

	ret = lttng_strncpy(lsm.session.name, handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	COPY_DOMAIN_PACKED(lsm.domain, handle->domain);

	size = uri_parse_str_urls(control_url, data_url, &uris);
	if (size < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	lsm.u.uri.size = size;

	ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(
		&lsm, uris, sizeof(struct lttng_uri) * size, nullptr);

	free(uris);
error:
	return ret;
}

/*
 * [OBSOLETE]
 */
extern "C" LTTNG_EXPORT int lttng_enable_consumer(struct lttng_handle *handle);
int lttng_enable_consumer(struct lttng_handle *handle __attribute__((unused)))
{
	return -ENOSYS;
}

/*
 * [OBSOLETE]
 */
extern "C" LTTNG_EXPORT int lttng_disable_consumer(struct lttng_handle *handle);
int lttng_disable_consumer(struct lttng_handle *handle __attribute__((unused)))
{
	return -ENOSYS;
}

/*
 * [OBSOLETE]
 */
extern "C" LTTNG_EXPORT int
_lttng_create_session_ext(const char *name, const char *url, const char *datetime);
int _lttng_create_session_ext(const char *name __attribute__((unused)),
			      const char *url __attribute__((unused)),
			      const char *datetime __attribute__((unused)))
{
	return -ENOSYS;
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
	uint8_t *pending = nullptr;

	if (session_name == nullptr) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_DATA_PENDING;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &pending);
	if (ret < 0) {
		goto end;
	} else if (ret != 1) {
		/* Unexpected payload size */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	} else if (!pending) {
		/* Internal error. */
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	ret = (int) *pending;
end:
	free(pending);
	return ret;
}

/*
 * Get the status of the kernel tracer
 *
 * Sets the value of the argument
 */
enum lttng_error_code lttng_get_kernel_tracer_status(enum lttng_kernel_tracer_status *out_status)
{
	if (out_status == nullptr) {
		return LTTNG_ERR_INVALID;
	}

	struct lttcomm_session_msg lsm = {};
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_KERNEL_TRACER_STATUS;

	uint32_t *raw_tracer_status = nullptr;
	const auto ask_ret = lttng_ctl_ask_sessiond(&lsm, (void **) &raw_tracer_status);

	const auto tracer_status =
		lttng::make_unique_wrapper<uint32_t, lttng::memory::free>(raw_tracer_status);

	if (ask_ret != 4) {
		return LTTNG_ERR_INVALID;
	}

	*out_status = (enum lttng_kernel_tracer_status) * tracer_status;
	return LTTNG_OK;
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
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_REGENERATE_METADATA;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, nullptr);
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
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_REGENERATE_STATEDUMP;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, nullptr);
	if (ret < 0) {
		goto end;
	}

	ret = 0;
end:
	return ret;
}

static int
_lttng_register_trigger(struct lttng_trigger *trigger, const char *name, bool generate_name)
{
	int ret;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_REGISTER_TRIGGER,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	lsm.u.trigger.is_trigger_anonymous = !name && !generate_name;
	struct lttcomm_session_msg *message_lsm;
	struct lttng_payload message;
	struct lttng_payload reply;
	struct lttng_trigger *reply_trigger = nullptr;
	enum lttng_domain_type domain_type;
	const struct lttng_credentials user_creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(geteuid()),
		.gid = LTTNG_OPTIONAL_INIT_UNSET,
	};
	const char *unused_trigger_name = nullptr;
	enum lttng_trigger_status trigger_status;

	lttng_payload_init(&message);
	lttng_payload_init(&reply);

	if (!trigger) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	trigger_status = lttng_trigger_get_name(trigger, &unused_trigger_name);
	if (trigger_status != LTTNG_TRIGGER_STATUS_UNSET) {
		/* Re-using already registered trigger. */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (name) {
		trigger_status = lttng_trigger_set_name(trigger, name);
		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	if (!trigger->creds.uid.is_set) {
		/* Use the client's credentials as the trigger credentials. */
		lttng_trigger_set_credentials(trigger, &user_creds);
	} else {
		/*
		 * Validate that either the current trigger credentials and the
		 * client credentials are identical or that the current user is
		 * root. The root user can register, unregister triggers for
		 * himself and other users.
		 *
		 * This check is also present on the sessiond side, using the
		 * credentials passed on the socket. These check are all
		 * "safety" checks.
		 */
		const struct lttng_credentials *trigger_creds =
			lttng_trigger_get_credentials(trigger);

		if (!lttng_credentials_is_equal_uid(trigger_creds, &user_creds)) {
			if (lttng_credentials_get_uid(&user_creds) != 0) {
				ret = -LTTNG_ERR_EPERM;
				goto end_unset_name;
			}
		}
	}

	if (!lttng_trigger_validate(trigger)) {
		ret = -LTTNG_ERR_INVALID_TRIGGER;
		goto end_unset_name;
	}

	domain_type = lttng_trigger_get_underlying_domain_type_restriction(trigger);

	lsm.domain.type = domain_type;

	ret = lttng_dynamic_buffer_append(&message.buffer, &lsm, sizeof(lsm));
	if (ret) {
		ret = -LTTNG_ERR_NOMEM;
		goto end_unset_name;
	}

	ret = lttng_trigger_serialize(trigger, &message);
	if (ret < 0) {
		ret = -LTTNG_ERR_UNK;
		goto end_unset_name;
	}

	/*
	 * This is needed to populate the trigger object size for the command
	 * header.
	 */
	message_lsm = (struct lttcomm_session_msg *) message.buffer.data;

	message_lsm->u.trigger.length = (uint32_t) message.buffer.size - sizeof(lsm);

	{
		struct lttng_payload_view message_view =
			lttng_payload_view_from_payload(&message, 0, -1);

		message_lsm->fd_count = lttng_payload_view_get_fd_handle_count(&message_view);
		ret = lttng_ctl_ask_sessiond_payload(&message_view, &reply);
		if (ret < 0) {
			goto end_unset_name;
		}
	}

	{
		struct lttng_payload_view reply_view =
			lttng_payload_view_from_payload(&reply, 0, reply.buffer.size);

		ret = lttng_trigger_create_from_payload(&reply_view, &reply_trigger);
		if (ret < 0) {
			ret = -LTTNG_ERR_INVALID_PROTOCOL;
			goto end_unset_name;
		}
	}

	if (name || generate_name) {
		ret = lttng_trigger_assign_name(trigger, reply_trigger);
		if (ret < 0) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	ret = 0;
	goto end;

end_unset_name:
	trigger_status = lttng_trigger_set_name(trigger, nullptr);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		ret = -LTTNG_ERR_UNK;
	}
end:
	lttng_payload_reset(&message);
	lttng_payload_reset(&reply);
	lttng_trigger_destroy(reply_trigger);
	return ret;
}

int lttng_register_trigger(struct lttng_trigger *trigger)
{
	/* Register an anonymous trigger. */
	return _lttng_register_trigger(trigger, nullptr, false);
}

enum lttng_error_code lttng_register_trigger_with_name(struct lttng_trigger *trigger,
						       const char *name)
{
	const int ret = _lttng_register_trigger(trigger, name, false);

	return ret == 0 ? LTTNG_OK : (enum lttng_error_code) - ret;
}

enum lttng_error_code lttng_register_trigger_with_automatic_name(struct lttng_trigger *trigger)
{
	const int ret = _lttng_register_trigger(trigger, nullptr, true);

	return ret == 0 ? LTTNG_OK : (enum lttng_error_code) - ret;
}

enum lttng_error_code lttng_error_query_execute(const struct lttng_error_query *query,
						const struct lttng_endpoint *endpoint,
						struct lttng_error_query_results **results)
{
	int ret;
	enum lttng_error_code ret_code;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_EXECUTE_ERROR_QUERY,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	struct lttng_payload message;
	struct lttng_payload reply;
	struct lttcomm_session_msg *message_lsm;

	lttng_payload_init(&message);
	lttng_payload_init(&reply);

	if (!query || !results) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	if (endpoint != lttng_session_daemon_command_endpoint) {
		ret_code = LTTNG_ERR_INVALID_ERROR_QUERY_TARGET;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&message.buffer, &lsm, sizeof(lsm));
	if (ret) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	ret = lttng_error_query_serialize(query, &message);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}

	message_lsm = (struct lttcomm_session_msg *) message.buffer.data;
	message_lsm->u.error_query.length = (uint32_t) message.buffer.size - sizeof(lsm);

	{
		struct lttng_payload_view message_view =
			lttng_payload_view_from_payload(&message, 0, -1);

		message_lsm->fd_count = lttng_payload_view_get_fd_handle_count(&message_view);
		ret = lttng_ctl_ask_sessiond_payload(&message_view, &reply);
		if (ret < 0) {
			ret_code = (lttng_error_code) -ret;
			goto end;
		}
	}

	{
		ssize_t reply_create_ret;
		struct lttng_payload_view reply_view =
			lttng_payload_view_from_payload(&reply, 0, reply.buffer.size);

		reply_create_ret =
			lttng_error_query_results_create_from_payload(&reply_view, results);
		if (reply_create_ret < 0) {
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			goto end;
		}
	}

	ret_code = LTTNG_OK;
end:
	lttng_payload_reset(&message);
	lttng_payload_reset(&reply);
	return ret_code;
}

int lttng_unregister_trigger(const struct lttng_trigger *trigger)
{
	int ret;
	struct lttcomm_session_msg lsm;
	struct lttcomm_session_msg *message_lsm;
	struct lttng_payload message;
	struct lttng_payload reply;
	struct lttng_trigger *copy = nullptr;
	const struct lttng_credentials user_creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(geteuid()),
		.gid = LTTNG_OPTIONAL_INIT_UNSET,
	};

	lttng_payload_init(&message);
	lttng_payload_init(&reply);

	if (!trigger) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	copy = lttng_trigger_copy(trigger);
	if (!copy) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	if (!copy->creds.uid.is_set) {
		/* Use the client credentials as the trigger credentials */
		lttng_trigger_set_credentials(copy, &user_creds);
	} else {
		/*
		 * Validate that either the current trigger credentials and the
		 * client credentials are identical or that the current user is
		 * root. The root user can register, unregister triggers for
		 * himself and other users.
		 *
		 * This check is also present on the sessiond side, using the
		 * credentials passed on the socket. These check are all
		 * "safety" checks.
		 */
		const struct lttng_credentials *trigger_creds = lttng_trigger_get_credentials(copy);
		if (!lttng_credentials_is_equal_uid(trigger_creds, &user_creds)) {
			if (lttng_credentials_get_uid(&user_creds) != 0) {
				ret = -LTTNG_ERR_EPERM;
				goto end;
			}
		}
	}

	if (!lttng_trigger_validate(copy)) {
		ret = -LTTNG_ERR_INVALID_TRIGGER;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_UNREGISTER_TRIGGER;

	ret = lttng_dynamic_buffer_append(&message.buffer, &lsm, sizeof(lsm));
	if (ret) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	ret = lttng_trigger_serialize(copy, &message);
	if (ret < 0) {
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	/*
	 * This is needed to populate the trigger object size for the command
	 * header and number of fds sent.
	 */
	message_lsm = (struct lttcomm_session_msg *) message.buffer.data;

	message_lsm->u.trigger.length = (uint32_t) message.buffer.size - sizeof(lsm);

	{
		struct lttng_payload_view message_view =
			lttng_payload_view_from_payload(&message, 0, -1);

		/*
		 * Update the message header with the number of fd that will be
		 * sent.
		 */
		message_lsm->fd_count = lttng_payload_view_get_fd_handle_count(&message_view);

		ret = lttng_ctl_ask_sessiond_payload(&message_view, &reply);
		if (ret < 0) {
			goto end;
		}
	}

	ret = 0;
end:
	lttng_trigger_destroy(copy);
	lttng_payload_reset(&message);
	lttng_payload_reset(&reply);
	return ret;
}

/*
 * Ask the session daemon for all registered triggers for the current user.
 *
 * Allocates and return an lttng_triggers set.
 * On error, returns a suitable lttng_error_code.
 */
enum lttng_error_code lttng_list_triggers(struct lttng_triggers **triggers)
{
	int ret;
	enum lttng_error_code ret_code = LTTNG_OK;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_TRIGGERS,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	struct lttng_triggers *local_triggers = nullptr;
	struct lttng_payload reply;
	struct lttng_payload_view lsm_view =
		lttng_payload_view_init_from_buffer((const char *) &lsm, 0, sizeof(lsm));

	lttng_payload_init(&reply);

	ret = lttng_ctl_ask_sessiond_payload(&lsm_view, &reply);
	if (ret < 0) {
		ret_code = (enum lttng_error_code) - ret;
		goto end;
	}

	{
		struct lttng_payload_view reply_view =
			lttng_payload_view_from_payload(&reply, 0, reply.buffer.size);

		ret = lttng_triggers_create_from_payload(&reply_view, &local_triggers);
		if (ret < 0) {
			ret_code = LTTNG_ERR_FATAL;
			goto end;
		}
	}

	*triggers = local_triggers;
	local_triggers = nullptr;
end:
	lttng_payload_reset(&reply);
	lttng_triggers_destroy(local_triggers);
	return ret_code;
}

/*
 * lib constructor.
 */
static void __attribute__((constructor)) init()
{
	/* Set default session group */
	lttng_set_tracing_group(DEFAULT_TRACING_GROUP);
}

/*
 * lib destructor.
 */
static void __attribute__((destructor)) lttng_ctl_exit()
{
	free(tracing_group);
}
