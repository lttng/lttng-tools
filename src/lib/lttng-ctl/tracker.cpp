/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/domain.h>
#include <lttng/lttng-error.h>

#include "lttng-ctl-helper.hpp"
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/tracker.hpp>
#include <lttng/tracker.h>
#include <type_traits>

struct lttng_process_attr_tracker_handle {
	char *session_name;
	enum lttng_domain_type domain;
	enum lttng_process_attr process_attr;
	struct lttng_process_attr_values *inclusion_set;
};

void lttng_process_attr_tracker_handle_destroy(
		struct lttng_process_attr_tracker_handle *tracker)
{
	if (!tracker) {
		return;
	}

	lttng_process_attr_values_destroy(tracker->inclusion_set);
	free(tracker->session_name);
	free(tracker);
}

enum lttng_error_code lttng_session_get_tracker_handle(const char *session_name,
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		struct lttng_process_attr_tracker_handle **out_tracker_handle)
{
	enum lttng_error_code ret_code = LTTNG_OK;
	struct lttng_process_attr_tracker_handle *handle = NULL;
	enum lttng_process_attr_tracker_handle_status status;
	enum lttng_tracking_policy policy;

	if (!session_name || !out_tracker_handle) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

	if (domain != LTTNG_DOMAIN_KERNEL && domain != LTTNG_DOMAIN_UST) {
		ret_code = LTTNG_ERR_UNSUPPORTED_DOMAIN;
		goto error;
	}

	handle = zmalloc<lttng_process_attr_tracker_handle>();
	if (!handle) {
		ret_code = LTTNG_ERR_NOMEM;
		goto error;
	}

	handle->session_name = strdup(session_name);
	if (!handle->session_name) {
		ret_code = LTTNG_ERR_NOMEM;
		goto error;
	}

	handle->domain = domain;
	handle->process_attr = process_attr;

	/*
	 * Use the `get_tracking_policy` command to validate the tracker's
	 * existence.
	 */
	status = lttng_process_attr_tracker_handle_get_tracking_policy(
			handle, &policy);
	switch (status) {
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK:
		break;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST:
		ret_code = LTTNG_ERR_SESSION_NOT_EXIST;
		goto error;
	default:
		ret_code = LTTNG_ERR_UNK;
		goto error;
	}

	*out_tracker_handle = handle;
	return ret_code;
error:
	lttng_process_attr_tracker_handle_destroy(handle);
	return ret_code;
}

enum lttng_process_attr_tracker_handle_status
lttng_process_attr_tracker_handle_get_tracking_policy(
		const struct lttng_process_attr_tracker_handle *tracker,
		enum lttng_tracking_policy *policy)
{
	void *reply = NULL;
	int reply_ret, copy_ret;
	enum lttng_process_attr_tracker_handle_status status =
			LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_POLICY,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};

	if (!tracker || !policy) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;
		goto end;
	}

	copy_ret = lttng_strncpy(lsm.session.name, tracker->session_name,
			sizeof(lsm.session.name));
	if (copy_ret) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;
		goto end;
	}

	lsm.domain.type = tracker->domain;
	lsm.u.process_attr_tracker_get_tracking_policy.process_attr =
			(int32_t) tracker->process_attr;

	/* Command returns a session descriptor on success. */
	reply_ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(
			&lsm, NULL, 0, &reply);
	if (reply_ret != sizeof(uint32_t)) {
		if (reply_ret == -LTTNG_ERR_SESSION_NOT_EXIST ||
				reply_ret == -LTTNG_ERR_SESS_NOT_FOUND) {
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST;
		} else {
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR;
		}
		goto end;
	}

	*policy = (enum lttng_tracking_policy)(*((const uint32_t *) reply));
end:
	free(reply);
	return status;
}

enum lttng_process_attr_tracker_handle_status
lttng_process_attr_tracker_handle_set_tracking_policy(
		const struct lttng_process_attr_tracker_handle *tracker,
		enum lttng_tracking_policy policy)
{
	int reply_ret, copy_ret;
	enum lttng_process_attr_tracker_handle_status status =
			LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_SET_POLICY,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};

	if (!tracker) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;
		goto end;
	}

	copy_ret = lttng_strncpy(lsm.session.name, tracker->session_name,
				 sizeof(lsm.session.name));
	if (copy_ret) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;
		goto end;
	}

	lsm.domain.type = tracker->domain;
	lsm.u.process_attr_tracker_set_tracking_policy.process_attr =
			(int32_t) tracker->process_attr;
	lsm.u.process_attr_tracker_set_tracking_policy.tracking_policy =
			(int32_t) policy;

	/* Command returns a session descriptor on success. */
	reply_ret = lttng_ctl_ask_sessiond(&lsm, NULL);
	if (reply_ret < 0) {
		if (reply_ret == -LTTNG_ERR_SESSION_NOT_EXIST) {
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST;
		} else {
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR;
		}
		goto end;
	}
end:
	return status;
}

#define DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(command_upper,                                                 \
		command_lower, process_attr_name, value_type_name,                                                   \
		value_type_c, value_type_enum)                                                                       \
	enum lttng_process_attr_tracker_handle_status                                                                \
			lttng_process_attr_##process_attr_name##_tracker_handle_##command_lower##_##value_type_name( \
					const struct lttng_process_attr_tracker_handle                               \
							*tracker,                                                    \
					value_type_c value)                                                          \
	{                                                                                                            \
		int ret;                                                                                             \
		enum lttng_process_attr_tracker_handle_status status =                                               \
				LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK;                                         \
		struct lttcomm_session_msg lsm = {                                                                   \
			.cmd_type = LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_##command_upper##_INCLUDE_VALUE,                      \
			.session = {},                                                                               \
			.domain = {},                                                                                \
			.u = {},                                                                                     \
			.fd_count = 0,                                                                               \
		};                                                                                                   \
                                                                                                                     \
		if (!tracker) {                                                                                      \
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;                                   \
			goto end;                                                                                    \
		}                                                                                                    \
                                                                                                                     \
		ret = lttng_strncpy(lsm.session.name, tracker->session_name,                                         \
				sizeof(lsm.session.name));                                                           \
		if (ret) {                                                                                           \
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;                                   \
			goto end;                                                                                    \
		}                                                                                                    \
                                                                                                                     \
		lsm.domain.type = tracker->domain;                                                                   \
		lsm.u.process_attr_tracker_add_remove_include_value                                                  \
				.process_attr =                                                                      \
				(int32_t) tracker->process_attr;                                                     \
		lsm.u.process_attr_tracker_add_remove_include_value                                                  \
				.value_type = (uint32_t)                                                             \
				LTTNG_PROCESS_ATTR_VALUE_TYPE_##value_type_enum;                                     \
                                                                                                                     \
		if (std::is_signed<value_type_c>::value) {                                                                       \
			lsm.u.process_attr_tracker_add_remove_include_value                                          \
					.integral_value.u._signed = value;                                           \
		} else {                                                                                             \
			lsm.u.process_attr_tracker_add_remove_include_value                                          \
					.integral_value.u._unsigned = value;                                         \
		}                                                                                                    \
                                                                                                                     \
		ret = lttng_ctl_ask_sessiond(&lsm, NULL);                                                            \
		if (ret < 0) {                                                                                       \
			switch (-ret) {                                                                              \
			case LTTNG_ERR_PROCESS_ATTR_EXISTS:                                                          \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_EXISTS;                            \
				break;                                                                               \
			case LTTNG_ERR_PROCESS_ATTR_MISSING:                                                         \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_MISSING;                           \
				break;                                                                               \
			case LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY:                                 \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID_TRACKING_POLICY;           \
				break;                                                                               \
			default:                                                                                     \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR;                             \
			}                                                                                            \
		}                                                                                                    \
	end:                                                                                                         \
		return status;                                                                                       \
	}

#define DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(command_upper,                                                   \
		command_lower, process_attr_name, value_type_name,                                                   \
		value_type_enum)                                                                                     \
	enum lttng_process_attr_tracker_handle_status                                                                \
			lttng_process_attr_##process_attr_name##_tracker_handle_##command_lower##_##value_type_name( \
					const struct lttng_process_attr_tracker_handle                               \
							*tracker,                                                    \
					const char *value)                                                           \
	{                                                                                                            \
		int ret;                                                                                             \
		enum lttng_process_attr_tracker_handle_status status =                                               \
				LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK;                                         \
		struct lttcomm_session_msg lsm = {                                                                   \
			.cmd_type = LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_##command_upper##_INCLUDE_VALUE,                      \
			.session = {},                                                                               \
			.domain = {},                                                                                \
			.u = {},                                                                                     \
			.fd_count = 0,                                                                               \
		};                                                                                                   \
		const size_t len = value ? strlen(value) + 1 : 0;                                                    \
                                                                                                                     \
		if (!tracker || !value) {                                                                            \
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;                                   \
			goto end;                                                                                    \
		}                                                                                                    \
                                                                                                                     \
		ret = lttng_strncpy(lsm.session.name, tracker->session_name,                                         \
				sizeof(lsm.session.name));                                                           \
		if (ret) {                                                                                           \
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;                                   \
			goto end;                                                                                    \
		}                                                                                                    \
                                                                                                                     \
		lsm.domain.type = tracker->domain;                                                                   \
		lsm.u.process_attr_tracker_add_remove_include_value                                                  \
				.process_attr =                                                                      \
				(int32_t) tracker->process_attr;                                                     \
		lsm.u.process_attr_tracker_add_remove_include_value.name_len =                                       \
				(uint32_t) len;                                                                      \
		lsm.u.process_attr_tracker_add_remove_include_value                                                  \
				.value_type = (uint32_t)                                                             \
				LTTNG_PROCESS_ATTR_VALUE_TYPE_##value_type_enum;                                     \
                                                                                                                     \
		ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(                                                   \
				&lsm, value, len, NULL);                                                             \
		if (ret < 0) {                                                                                       \
			switch (-ret) {                                                                              \
			case LTTNG_ERR_PROCESS_ATTR_EXISTS:                                                          \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_EXISTS;                            \
				break;                                                                               \
			case LTTNG_ERR_PROCESS_ATTR_MISSING:                                                         \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_MISSING;                           \
				break;                                                                               \
			case LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY:                                 \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID_TRACKING_POLICY;           \
				break;                                                                               \
			case LTTNG_ERR_USER_NOT_FOUND:                                                               \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_USER_NOT_FOUND;                    \
				break;                                                                               \
			case LTTNG_ERR_GROUP_NOT_FOUND:                                                              \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_GROUP_NOT_FOUND;                   \
				break;                                                                               \
			default:                                                                                     \
				status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR;                             \
			}                                                                                            \
		}                                                                                                    \
	end:                                                                                                         \
		return status;                                                                                       \
	}

/* PID */
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		ADD, add, process_id, pid, pid_t, PID);
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		REMOVE, remove, process_id, pid, pid_t, PID);

/* VPID */
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		ADD, add, virtual_process_id, pid, pid_t, PID);
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		REMOVE, remove, virtual_process_id, pid, pid_t, PID);

/* UID */
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		ADD, add, user_id, uid, uid_t, UID);
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		REMOVE, remove, user_id, uid, uid_t, UID);
DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(
		ADD, add, user_id, user_name, USER_NAME);
DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(
		REMOVE, remove, user_id, user_name, USER_NAME);

/* VUID */
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		ADD, add, virtual_user_id, uid, uid_t, UID);
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		REMOVE, remove, virtual_user_id, uid, uid_t, UID);
DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(
		ADD, add, virtual_user_id, user_name, USER_NAME);
DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(
		REMOVE, remove, virtual_user_id, user_name, USER_NAME);

/* GID */
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		ADD, add, group_id, gid, gid_t, GID);
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		REMOVE, remove, group_id, gid, gid_t, GID);
DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(
		ADD, add, group_id, group_name, GROUP_NAME);
DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(
		REMOVE, remove, group_id, group_name, GROUP_NAME);

/* VGID */
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		ADD, add, virtual_group_id, gid, gid_t, GID);
DEFINE_TRACKER_ADD_REMOVE_INTEGRAL_VALUE_FUNC(
		REMOVE, remove, virtual_group_id, gid, gid_t, GID);
DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(
		ADD, add, virtual_group_id, group_name, GROUP_NAME);
DEFINE_TRACKER_ADD_REMOVE_STRING_VALUE_FUNC(
		REMOVE, remove, virtual_group_id, group_name, GROUP_NAME);

enum lttng_process_attr_tracker_handle_status
lttng_process_attr_tracker_handle_get_inclusion_set(
		struct lttng_process_attr_tracker_handle *tracker,
		const struct lttng_process_attr_values **values)
{
	char *reply = NULL;
	int reply_ret, copy_ret;
	enum lttng_process_attr_tracker_handle_status status =
			LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_INCLUSION_SET,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	struct lttng_buffer_view inclusion_set_view;
	ssize_t inclusion_set_ret;

	if (!tracker || !values) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;
		goto end;
	}

	lttng_process_attr_values_destroy(tracker->inclusion_set);
	tracker->inclusion_set = NULL;

	copy_ret = lttng_strncpy(lsm.session.name, tracker->session_name,
			sizeof(lsm.session.name));
	if (copy_ret) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID;
		goto end;
	}

	lsm.domain.type = tracker->domain;
	lsm.u.process_attr_tracker_get_tracking_policy.process_attr =
			(int32_t) tracker->process_attr;

	/* Command returns a session descriptor on success. */
	reply_ret = lttng_ctl_ask_sessiond_varlen_no_cmd_header(
			&lsm, NULL, 0, (void **) &reply);
	if (reply_ret < 0) {
		if (reply_ret == -LTTNG_ERR_SESSION_NOT_EXIST) {
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST;
		} else if (reply_ret ==
				-LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY) {
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID_TRACKING_POLICY;
		} else {
			status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR;
		}
		goto end;
	} else if (reply_ret == 0) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_COMMUNICATION_ERROR;
		goto end;
	}

	inclusion_set_view = lttng_buffer_view_init(reply, 0, reply_ret);
	if (!inclusion_set_view.data) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_COMMUNICATION_ERROR;
		goto end;
	}

	inclusion_set_ret = lttng_process_attr_values_create_from_buffer(
			tracker->domain, tracker->process_attr,
			&inclusion_set_view, &tracker->inclusion_set);
	if (inclusion_set_ret < 0) {
		status = LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_COMMUNICATION_ERROR;
		goto end;
	}
	*values = tracker->inclusion_set;
end:
	free(reply);
	return status;
}

enum lttng_process_attr_values_status lttng_process_attr_values_get_count(
		const struct lttng_process_attr_values *values,
		unsigned int *count)
{
	enum lttng_process_attr_values_status status =
			LTTNG_PROCESS_ATTR_VALUES_STATUS_OK;

	if (!values || !count) {
		status = LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID;
		goto end;
	}

	*count = _lttng_process_attr_values_get_count(values);
end:
	return status;
}

enum lttng_process_attr_value_type lttng_process_attr_values_get_type_at_index(
		const struct lttng_process_attr_values *values,
		unsigned int index)
{
	enum lttng_process_attr_value_type type;
	const struct process_attr_value *value;

	if (!values) {
		type = LTTNG_PROCESS_ATTR_VALUE_TYPE_INVALID;
		goto end;
	}

	if (_lttng_process_attr_values_get_count(values) <= index) {
		type = LTTNG_PROCESS_ATTR_VALUE_TYPE_INVALID;
		goto end;
	}

	value = lttng_process_attr_tracker_values_get_at_index(values, index);
	type = value->type;
end:
	return type;
}

#define DEFINE_LTTNG_PROCESS_ATTR_VALUES_GETTER(                                       \
		value_type_name, value_type, expected_value_type)                      \
	enum lttng_process_attr_values_status                                          \
			lttng_process_attr_values_get_##value_type_name##_at_index(    \
					const struct lttng_process_attr_values         \
							*values,                       \
					unsigned int index,                            \
					value_type *out_value)                         \
	{                                                                              \
		enum lttng_process_attr_values_status status =                         \
				LTTNG_PROCESS_ATTR_VALUES_STATUS_OK;                   \
		const struct process_attr_value *value;                                \
                                                                                       \
		if (!values) {                                                         \
			status = LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID;             \
			goto end;                                                      \
		}                                                                      \
                                                                                       \
		if (_lttng_process_attr_values_get_count(values) <= index) {           \
			status = LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID;             \
			goto end;                                                      \
		}                                                                      \
                                                                                       \
		value = lttng_process_attr_tracker_values_get_at_index(                \
				values, index);                                        \
		if (value->type !=                                                     \
				LTTNG_PROCESS_ATTR_VALUE_TYPE_##expected_value_type) { \
			status = LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID_TYPE;        \
			goto end;                                                      \
		}                                                                      \
		*out_value = value->value.value_type_name;                             \
	end:                                                                           \
		return status;                                                         \
	}

DEFINE_LTTNG_PROCESS_ATTR_VALUES_GETTER(pid, pid_t, PID);
DEFINE_LTTNG_PROCESS_ATTR_VALUES_GETTER(uid, uid_t, UID);
DEFINE_LTTNG_PROCESS_ATTR_VALUES_GETTER(gid, gid_t, GID);
DEFINE_LTTNG_PROCESS_ATTR_VALUES_GETTER(user_name, const char *, USER_NAME);
DEFINE_LTTNG_PROCESS_ATTR_VALUES_GETTER(group_name, const char *, GROUP_NAME);

static enum lttng_error_code handle_status_to_error_code(
		enum lttng_process_attr_tracker_handle_status handle_status)
{
	switch (handle_status) {
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID_TRACKING_POLICY:
		return LTTNG_ERR_INVALID;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST:
		return LTTNG_ERR_SESSION_NOT_EXIST;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_COMMUNICATION_ERROR:
		return LTTNG_ERR_INVALID_PROTOCOL;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_EXISTS:
		return LTTNG_ERR_PID_TRACKED;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_MISSING:
		return LTTNG_ERR_PID_NOT_TRACKED;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK:
		return LTTNG_OK;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR:
	default:
		/* fall-through. */
		return LTTNG_ERR_UNK;
	}
}

/*
 * Add PID to session tracker.
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_track_pid(struct lttng_handle *handle, int pid)
{
	enum lttng_error_code ret_code;
	struct lttng_process_attr_tracker_handle *tracker_handle = NULL;
	enum lttng_process_attr_tracker_handle_status handle_status;
	enum lttng_tracking_policy policy;
	enum lttng_process_attr process_attr;

	if (!handle) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	process_attr = handle->domain.type == LTTNG_DOMAIN_KERNEL ?
				       LTTNG_PROCESS_ATTR_PROCESS_ID :
				       LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID;

	ret_code = lttng_session_get_tracker_handle(handle->session_name,
			handle->domain.type,
			process_attr, &tracker_handle);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	if (pid == -1) {
		handle_status = lttng_process_attr_tracker_handle_set_tracking_policy(
				tracker_handle,
				LTTNG_TRACKING_POLICY_INCLUDE_ALL);
		ret_code = handle_status_to_error_code(handle_status);
		goto end;
	}

	handle_status = lttng_process_attr_tracker_handle_get_tracking_policy(
		tracker_handle, &policy);
	if (handle_status != LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
		ret_code = handle_status_to_error_code(handle_status);
		goto end;
	}

	if (policy != LTTNG_TRACKING_POLICY_INCLUDE_SET) {
		handle_status = lttng_process_attr_tracker_handle_set_tracking_policy(
			tracker_handle,
			LTTNG_TRACKING_POLICY_INCLUDE_SET);
		if (handle_status != LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
			ret_code = handle_status_to_error_code(handle_status);
			goto end;
		}
	}

	handle_status = process_attr == LTTNG_PROCESS_ATTR_PROCESS_ID ?
					lttng_process_attr_process_id_tracker_handle_add_pid(
							tracker_handle,
							(pid_t) pid) :
					lttng_process_attr_virtual_process_id_tracker_handle_add_pid(
							tracker_handle,
							(pid_t) pid);
	ret_code = handle_status_to_error_code(handle_status);
end:
	lttng_process_attr_tracker_handle_destroy(tracker_handle);
	return ret_code == LTTNG_OK ? 0 : -ret_code;
}

/*
 * Remove PID from session tracker.
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_untrack_pid(struct lttng_handle *handle, int pid)
{
	enum lttng_error_code ret_code;
	struct lttng_process_attr_tracker_handle *tracker_handle = NULL;
	enum lttng_process_attr_tracker_handle_status handle_status;
	enum lttng_tracking_policy policy;
	enum lttng_process_attr process_attr;

	if (!handle) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	process_attr = handle->domain.type == LTTNG_DOMAIN_KERNEL ?
				       LTTNG_PROCESS_ATTR_PROCESS_ID :
				       LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID;
	ret_code = lttng_session_get_tracker_handle(handle->session_name,
			handle->domain.type, process_attr, &tracker_handle);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	if (pid == -1) {
		handle_status = lttng_process_attr_tracker_handle_set_tracking_policy(
				tracker_handle,
				LTTNG_TRACKING_POLICY_EXCLUDE_ALL);
		ret_code = handle_status_to_error_code(handle_status);
		goto end;
	}

	handle_status = lttng_process_attr_tracker_handle_get_tracking_policy(
		tracker_handle, &policy);
	if (handle_status != LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
		ret_code = handle_status_to_error_code(handle_status);
		goto end;
	}

	if (policy == LTTNG_TRACKING_POLICY_EXCLUDE_ALL) {
		ret_code = LTTNG_ERR_PID_NOT_TRACKED;
		goto end;
	} else if (policy == LTTNG_TRACKING_POLICY_INCLUDE_ALL) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	handle_status = process_attr == LTTNG_PROCESS_ATTR_PROCESS_ID ?
					lttng_process_attr_process_id_tracker_handle_remove_pid(
							tracker_handle,
							(pid_t) pid) :
					lttng_process_attr_virtual_process_id_tracker_handle_remove_pid(
							tracker_handle,
							(pid_t) pid);
	if (handle_status == LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID_TRACKING_POLICY) {
		ret_code = LTTNG_ERR_PID_NOT_TRACKED;
	}
end:
	lttng_process_attr_tracker_handle_destroy(tracker_handle);
	return ret_code == LTTNG_OK ? 0 : -ret_code;
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
		int *_enabled,
		int32_t **_pids,
		size_t *_nr_pids)
{
	enum lttng_error_code ret_code;
	struct lttng_process_attr_tracker_handle *tracker_handle = NULL;
	enum lttng_process_attr_tracker_handle_status handle_status;
	const struct lttng_process_attr_values *values;
	enum lttng_tracking_policy policy;
	unsigned int pid_count, i;
	int32_t *pid_array = NULL;

	if (!handle || !_enabled || !_pids || !_nr_pids) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	ret_code = lttng_session_get_tracker_handle(handle->session_name,
			handle->domain.type,
			LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID, &tracker_handle);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	while (true) {
		handle_status = lttng_process_attr_tracker_handle_get_inclusion_set(
				tracker_handle, &values);
		if (handle_status ==
				LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
			policy = LTTNG_TRACKING_POLICY_INCLUDE_SET;
			break;
		} else if (handle_status !=
				LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID_TRACKING_POLICY) {
			ret_code = handle_status_to_error_code(handle_status);
			goto end;
		}

		handle_status = lttng_process_attr_tracker_handle_get_tracking_policy(
				tracker_handle, &policy);
		if (handle_status !=
				LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
			ret_code = handle_status_to_error_code(handle_status);
			goto end;
		}

		/* Tracking policy changed in the meantime, retry. */
		if (policy == LTTNG_TRACKING_POLICY_INCLUDE_SET) {
			continue;
		}
		break;
	}

	switch (policy) {
	case LTTNG_TRACKING_POLICY_INCLUDE_ALL:
		*_enabled = 0;
		goto end;
	case LTTNG_TRACKING_POLICY_EXCLUDE_ALL:
		*_enabled = 1;
		pid_count = 0;
		break;
	case LTTNG_TRACKING_POLICY_INCLUDE_SET:
	{
		const enum lttng_process_attr_values_status values_status =
				lttng_process_attr_values_get_count(
						values, &pid_count);

		if (values_status != LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			ret_code = LTTNG_ERR_UNK;
			goto end;
		}
		break;
	}
	default:
		ret_code = LTTNG_ERR_INVALID_PROTOCOL;
		goto end;
	}

	pid_array = calloc<int32_t>(pid_count);
	if (!pid_array) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Extract values to a raw array. */
	for (i = 0; i < pid_count; i++) {
		pid_t pid;
		const enum lttng_process_attr_values_status values_status =
				lttng_process_attr_values_get_pid_at_index(
						values, i, &pid);

		if (values_status != LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			ret_code = LTTNG_ERR_UNK;
			goto end;
		}
		pid_array[i] = (int32_t) pid;
	}
	*_nr_pids = (size_t) pid_count;
	*_pids = pid_array;
	pid_array = NULL;
end:
	lttng_process_attr_tracker_handle_destroy(tracker_handle);
	free(pid_array);
	return ret_code == LTTNG_OK ? 0 : -ret_code;
}
