/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/utils.hpp>

#include "clear.hpp"
#include "session.hpp"
#include "ust-app.hpp"
#include "kernel.hpp"
#include "cmd.hpp"

namespace {
struct cmd_clear_session_reply_context {
	int reply_sock_fd;
};
} /* namespace */

static
void cmd_clear_session_reply(const struct ltt_session *session,
		void *_reply_context)
{
	int ret;
	ssize_t comm_ret;
	const struct cmd_clear_session_reply_context *reply_context =
			(cmd_clear_session_reply_context *) _reply_context;
	struct lttcomm_lttng_msg llm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_CLEAR_SESSION,
		.ret_code = LTTNG_OK,
		.pid = UINT32_MAX,
		.cmd_header_size = 0,
		.data_size = 0,
		.fd_count = 0,
	};

	DBG("End of clear command: replying to client");
	comm_ret = lttcomm_send_unix_sock(reply_context->reply_sock_fd,
			&llm, sizeof(llm));
	if (comm_ret != (ssize_t) sizeof(llm)) {
		ERR("Failed to send result of session \"%s\" clear to client",
				session->name);
	}
	ret = close(reply_context->reply_sock_fd);
	if (ret) {
		PERROR("Failed to close client socket in deferred session clear reply");
	}
	free(_reply_context);
}

int cmd_clear_session(struct ltt_session *session, int *sock_fd)
{
	int ret = LTTNG_OK;
	struct cmd_clear_session_reply_context *reply_context = NULL;
	bool session_was_active = false;
	struct ltt_kernel_session *ksession;
	struct ltt_ust_session *usess;

	ksession = session->kernel_session;
	usess = session->ust_session;

	if (sock_fd) {
		reply_context = zmalloc<cmd_clear_session_reply_context>();
		if (!reply_context) {
			ret = LTTNG_ERR_NOMEM;
			goto end;
		}
		reply_context->reply_sock_fd = *sock_fd;
	}

	if (!session->has_been_started) {
		 /*
		  * Nothing to be cleared, this is not an error: there is
		  * indeed nothing to do, and there is no reason why we
		  * should return an error to the user.
		  */
		 goto end;
	}

	/* Unsupported feature in lttng-relayd before 2.11. */
	if (session->consumer->type == CONSUMER_DST_NET &&
			(session->consumer->relay_major_version == 2 &&
			session->consumer->relay_minor_version < 12)) {
		ret = LTTNG_ERR_CLEAR_NOT_AVAILABLE_RELAY;
		goto end;
	}
	if (session->consumer->type == CONSUMER_DST_NET &&
			!session->consumer->relay_allows_clear) {
		ret = LTTNG_ERR_CLEAR_NOT_AVAILABLE_RELAY;
		goto end;
	}

	/*
	 * After a stop followed by a clear, all subsequent clear are
	 * effect-less until start is performed.
	 */
	if (session->cleared_after_last_stop) {
		ret = LTTNG_OK;
		goto end;
	}

	/*
	 * After a stop followed by a rotation, all subsequent clear are effect-less
	 * until start is performed.
	 */
	if (session->rotated_after_last_stop) {
		ret = LTTNG_OK;
		goto end;
	}

	session_was_active = session->active;
	if (session_was_active) {
		ret = stop_kernel_session(ksession);
		if (ret != LTTNG_OK) {
			goto end;
		}
		if (usess && usess->active) {
			ret = ust_app_stop_trace_all(usess);
			if (ret < 0) {
				ret = LTTNG_ERR_UST_STOP_FAIL;
				goto end;
			}
		}
	}

	/*
	 * Clear active kernel and UST session buffers.
	 */
	if (session->kernel_session) {
		ret = kernel_clear_session(session);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}
	if (session->ust_session) {
		ret = ust_app_clear_session(session);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	if (session->output_traces) {
		/*
		 * Use rotation to delete local and remote stream files.
		 */
		if (reply_context) {
			ret = session_add_clear_notifier(session,
					cmd_clear_session_reply,
					(void *) reply_context);
			if (ret) {
				ret = LTTNG_ERR_FATAL;
				goto end;
			}
			/*
			 * On success, ownership of reply_context has been
			 * passed to session_add_clear_notifier().
			 */
			reply_context = NULL;
			*sock_fd = -1;
		}
		ret = cmd_rotate_session(session, NULL, true,
			LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}
	if (!session->active) {
		session->cleared_after_last_stop = true;
	}
	if (session_was_active) {
		/* Kernel tracing */
		if (ksession != NULL) {
			DBG("Start kernel tracing session \"%s\"",
					session->name);
			ret = start_kernel_session(ksession);
			if (ret != LTTNG_OK) {
				goto end;
			}
		}

		/* Flag session that trace should start automatically */
		if (usess) {
			int int_ret = ust_app_start_trace_all(usess);

			if (int_ret < 0) {
				ret = LTTNG_ERR_UST_START_FAIL;
				goto end;
			}
		}

		/*
		 * Open a packet in every stream of the session to ensure that
		 * viewers can correctly identify the boundaries of the periods
		 * during which tracing was active for this session.
		 */
		ret = session_open_packets(session);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}
	ret = LTTNG_OK;
end:
	free(reply_context);
	return ret;
}
