/*
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef AGENT_COMM
#define AGENT_COMM

#include <common/compiler.hpp>
#include <common/macros.hpp>

#include <lttng/lttng.h>

#include <stdint.h>

/*
 * Command value passed in the header.
 */
enum lttcomm_agent_command {
	AGENT_CMD_LIST = 1,
	AGENT_CMD_ENABLE = 2,
	AGENT_CMD_DISABLE = 3,
	AGENT_CMD_REG_DONE = 4, /* End registration process. */
	AGENT_CMD_APP_CTX_ENABLE = 5,
	AGENT_CMD_APP_CTX_DISABLE = 6,
};

/*
 * Return codes from the agent.
 */
enum lttcomm_agent_ret_code {
	/* Success, assumed to be the first entry */
	AGENT_RET_CODE_SUCCESS = 1,
	/* Invalid command */
	AGENT_RET_CODE_INVALID = 2,
	/* Unknown logger name */
	AGENT_RET_CODE_UNKNOWN_NAME = 3,
	AGENT_RET_CODE_NR,
};

/*
 * Agent application communication header.
 */
struct lttcomm_agent_hdr {
	uint64_t data_size; /* data size following this header */
	uint32_t cmd; /* Enum of agent command. */
	uint32_t cmd_version; /* command version */
} LTTNG_PACKED;

/*
 * Enable event command payload. Will be immediately followed by the
 * variable-length string representing the filter expression.
 */
struct lttcomm_agent_enable_event {
	uint32_t loglevel_value;
	uint32_t loglevel_type;
	char name[LTTNG_SYMBOL_NAME_LEN];
	uint32_t filter_expression_length;
} LTTNG_PACKED;

/*
 * Disable event command payload.
 */
struct lttcomm_agent_disable_event {
	char name[LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

/*
 * Generic reply coming from the agent.
 */
struct lttcomm_agent_generic_reply {
	uint32_t ret_code;
} LTTNG_PACKED;

/*
 * List command reply header.
 */
struct lttcomm_agent_list_reply_hdr {
	uint32_t ret_code;
	uint32_t data_size;
} LTTNG_PACKED;

/*
 * List command reply payload coming from the agent.
 */
struct lttcomm_agent_list_reply {
	uint32_t nb_event;
	/* List of event name each of them ending by a NULL byte. */
	char payload[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
} LTTNG_PACKED;

#endif /* AGENT_COMM */
