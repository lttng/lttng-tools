/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "lttng-ctl-helper.hpp"

#include <common/macros.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <lttng/location-internal.hpp>
#include <lttng/lttng-error.h>
#include <lttng/rotate-internal.hpp>
#include <lttng/rotation.h>

#include <string.h>

static enum lttng_rotation_status ask_rotation_info(struct lttng_rotation_handle *rotation_handle,
						    struct lttng_rotation_get_info_return **info)
{
	/* lsm.get_rotation_state.rotation_id */
	struct lttcomm_session_msg lsm;
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;
	int ret;

	if (!rotation_handle || !info) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_ROTATION_GET_INFO;
	lsm.u.get_rotation_info.rotation_id = rotation_handle->rotation_id;

	ret = lttng_strncpy(
		lsm.session.name, rotation_handle->session_name, sizeof(lsm.session.name));
	if (ret) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) info);
	if (ret < 0) {
		status = LTTNG_ROTATION_STATUS_ERROR;
		goto end;
	}
end:
	return status;
}

static struct lttng_trace_archive_location *
create_trace_archive_location_from_get_info(const struct lttng_rotation_get_info_return *info)
{
	struct lttng_trace_archive_location *location;

	switch (info->location_type) {
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL:
		location = lttng_trace_archive_location_local_create(
			info->location.local.absolute_path);
		break;
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY:
		location = lttng_trace_archive_location_relay_create(
			info->location.relay.host,
			(lttng_trace_archive_location_relay_protocol_type)
				info->location.relay.protocol,
			info->location.relay.ports.control,
			info->location.relay.ports.data,
			info->location.relay.relative_path);
		break;
	default:
		location = NULL;
		break;
	}
	return location;
}

enum lttng_rotation_status
lttng_rotation_handle_get_state(struct lttng_rotation_handle *rotation_handle,
				enum lttng_rotation_state *state)
{
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;
	struct lttng_rotation_get_info_return *info = NULL;

	if (!rotation_handle || !state) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	status = ask_rotation_info(rotation_handle, &info);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		goto end;
	}

	*state = (enum lttng_rotation_state) info->status;
	if (rotation_handle->archive_location || *state != LTTNG_ROTATION_STATE_COMPLETED) {
		/*
		 * The path is only provided by the sessiond once
		 * the session rotation is completed, but not expired.
		 */
		goto end;
	}

	/*
	 * Cache the location since the rotation may expire before the user
	 * has a chance to query it.
	 */
	rotation_handle->archive_location = create_trace_archive_location_from_get_info(info);
	if (!rotation_handle->archive_location) {
		status = LTTNG_ROTATION_STATUS_ERROR;
		goto end;
	}
end:
	free(info);
	return status;
}

enum lttng_rotation_status
lttng_rotation_handle_get_archive_location(struct lttng_rotation_handle *rotation_handle,
					   const struct lttng_trace_archive_location **location)
{
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;
	struct lttng_rotation_get_info_return *info = NULL;

	if (!rotation_handle || !location) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	/* Use the cached location we got from a previous query. */
	if (rotation_handle->archive_location) {
		*location = rotation_handle->archive_location;
		goto end;
	}

	status = ask_rotation_info(rotation_handle, &info);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		goto end;
	}

	if ((enum lttng_rotation_state) info->status != LTTNG_ROTATION_STATE_COMPLETED) {
		status = LTTNG_ROTATION_STATUS_UNAVAILABLE;
		goto end;
	}

	rotation_handle->archive_location = create_trace_archive_location_from_get_info(info);
	if (!rotation_handle->archive_location) {
		status = LTTNG_ROTATION_STATUS_ERROR;
		goto end;
	}
end:
	free(info);
	return status;
}

void lttng_rotation_handle_destroy(struct lttng_rotation_handle *rotation_handle)
{
	if (!rotation_handle) {
		return;
	}
	lttng_trace_archive_location_put(rotation_handle->archive_location);
	free(rotation_handle);
}

static int init_rotation_handle(struct lttng_rotation_handle *rotation_handle,
				const char *session_name,
				struct lttng_rotate_session_return *rotate_return)
{
	int ret;

	ret = lttng_strncpy(
		rotation_handle->session_name, session_name, sizeof(rotation_handle->session_name));
	if (ret) {
		goto end;
	}

	rotation_handle->rotation_id = rotate_return->rotation_id;
end:
	return ret;
}

/*
 * Rotate the output folder of the session.
 *
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_rotate_session(const char *session_name,
			 struct lttng_rotation_immediate_descriptor *descriptor
			 __attribute__((unused)),
			 struct lttng_rotation_handle **rotation_handle)
{
	struct lttcomm_session_msg lsm;
	struct lttng_rotate_session_return *rotate_return = NULL;
	int ret;
	size_t session_name_len;

	if (!session_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	session_name_len = strlen(session_name);
	if (session_name_len >= sizeof(lsm.session.name) ||
	    session_name_len >= member_sizeof(struct lttng_rotation_handle, session_name)) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_ROTATE_SESSION;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	/* Source length already validated. */
	LTTNG_ASSERT(ret == 0);

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &rotate_return);
	if (ret <= 0) {
		*rotation_handle = NULL;
		goto end;
	}

	*rotation_handle = zmalloc<lttng_rotation_handle>();
	if (!*rotation_handle) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	init_rotation_handle(*rotation_handle, session_name, rotate_return);

	ret = 0;

end:
	free(rotate_return);
	return ret;
}

/*
 * Update the automatic rotation parameters.
 * 'add' as true enables the provided schedule, false removes the shedule.
 *
 * The external API makes it appear as though arbitrary schedules can
 * be added or removed at will. However, the session daemon is
 * currently limited to one schedule per type (per session).
 *
 * The additional flexibility of the public API is offered for future
 * rotation schedules that could indicate more precise criteria than
 * size and time (e.g. a domain) where it could make sense to add
 * multiple schedules of a given type to a session.
 *
 * Hence, the exact schedule that the user wishes to remove (and not
 * just its type) must be passed so that the session daemon can
 * validate that is exists before clearing it.
 */
static enum lttng_rotation_status lttng_rotation_update_schedule(
	const char *session_name, const struct lttng_rotation_schedule *schedule, bool add)
{
	struct lttcomm_session_msg lsm;
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;
	int ret;

	if (!session_name || !schedule) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	if (strlen(session_name) >= sizeof(lsm.session.name)) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_ROTATION_SET_SCHEDULE;
	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	/* Source length already validated. */
	LTTNG_ASSERT(ret == 0);

	lsm.u.rotation_set_schedule.type = (uint32_t) schedule->type;
	switch (schedule->type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
	{
		uint64_t threshold;

		status = lttng_rotation_schedule_size_threshold_get_threshold(schedule, &threshold);
		if (status != LTTNG_ROTATION_STATUS_OK) {
			if (status == LTTNG_ROTATION_STATUS_UNAVAILABLE) {
				status = LTTNG_ROTATION_STATUS_INVALID;
			}
			goto end;
		}
		lsm.u.rotation_set_schedule.value = threshold;
		lsm.u.rotation_set_schedule.set = !!add;
		break;
	}
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
	{
		uint64_t period;

		status = lttng_rotation_schedule_periodic_get_period(schedule, &period);
		if (status != LTTNG_ROTATION_STATUS_OK) {
			if (status == LTTNG_ROTATION_STATUS_UNAVAILABLE) {
				status = LTTNG_ROTATION_STATUS_INVALID;
			}
			goto end;
		}
		lsm.u.rotation_set_schedule.value = period;
		lsm.u.rotation_set_schedule.set = !!add;
		break;
	}
	default:
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, NULL);
	if (ret >= 0) {
		goto end;
	}

	switch (-ret) {
	case LTTNG_ERR_ROTATION_SCHEDULE_SET:
		status = LTTNG_ROTATION_STATUS_SCHEDULE_ALREADY_SET;
		break;
	case LTTNG_ERR_ROTATION_SCHEDULE_NOT_SET:
		status = LTTNG_ROTATION_STATUS_INVALID;
		break;
	default:
		status = LTTNG_ROTATION_STATUS_ERROR;
	}
end:
	return status;
}

static struct lttng_rotation_schedules *lttng_rotation_schedules_create(void)
{
	return zmalloc<lttng_rotation_schedules>();
}

static void lttng_schedules_add(struct lttng_rotation_schedules *schedules,
				struct lttng_rotation_schedule *schedule)
{
	schedules->schedules[schedules->count++] = schedule;
}

static int get_schedules(const char *session_name, struct lttng_rotation_schedules **_schedules)
{
	int ret;
	struct lttcomm_session_msg lsm;
	struct lttng_session_list_schedules_return *schedules_comm = NULL;
	struct lttng_rotation_schedules *schedules = NULL;
	struct lttng_rotation_schedule *periodic = NULL, *size = NULL;

	if (!session_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_SESSION_LIST_ROTATION_SCHEDULES;
	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &schedules_comm);
	if (ret < 0) {
		goto end;
	}

	schedules = lttng_rotation_schedules_create();
	if (!schedules) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	if (schedules_comm->periodic.set == 1) {
		enum lttng_rotation_status status;

		periodic = lttng_rotation_schedule_periodic_create();
		if (!periodic) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		status = lttng_rotation_schedule_periodic_set_period(
			periodic, schedules_comm->periodic.value);
		if (status != LTTNG_ROTATION_STATUS_OK) {
			/*
			 * This would imply that the session daemon returned
			 * an invalid periodic rotation schedule value.
			 */
			ret = -LTTNG_ERR_UNK;
			goto end;
		}

		lttng_schedules_add(schedules, periodic);
		periodic = NULL;
	}

	if (schedules_comm->size.set == 1) {
		enum lttng_rotation_status status;

		size = lttng_rotation_schedule_size_threshold_create();
		if (!size) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		status = lttng_rotation_schedule_size_threshold_set_threshold(
			size, schedules_comm->size.value);
		if (status != LTTNG_ROTATION_STATUS_OK) {
			/*
			 * This would imply that the session daemon returned
			 * an invalid size threshold schedule value.
			 */
			ret = -LTTNG_ERR_UNK;
			goto end;
		}

		lttng_schedules_add(schedules, size);
		size = NULL;
	}

	ret = LTTNG_OK;
end:
	free(schedules_comm);
	free(periodic);
	free(size);
	*_schedules = schedules;
	return ret;
}

enum lttng_rotation_schedule_type
lttng_rotation_schedule_get_type(const struct lttng_rotation_schedule *schedule)
{
	return schedule ? schedule->type : LTTNG_ROTATION_SCHEDULE_TYPE_UNKNOWN;
}

struct lttng_rotation_schedule *lttng_rotation_schedule_size_threshold_create(void)
{
	struct lttng_rotation_schedule_size_threshold *schedule;

	schedule = zmalloc<lttng_rotation_schedule_size_threshold>();
	if (!schedule) {
		goto end;
	}

	schedule->parent.type = LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD;
end:
	return &schedule->parent;
}

enum lttng_rotation_status
lttng_rotation_schedule_size_threshold_get_threshold(const struct lttng_rotation_schedule *schedule,
						     uint64_t *size_threshold_bytes)
{
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;
	struct lttng_rotation_schedule_size_threshold *size_schedule;

	if (!schedule || !size_threshold_bytes ||
	    schedule->type != LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	size_schedule = lttng::utils::container_of(schedule,
						   &lttng_rotation_schedule_size_threshold::parent);
	if (size_schedule->size.set) {
		*size_threshold_bytes = size_schedule->size.bytes;
	} else {
		status = LTTNG_ROTATION_STATUS_UNAVAILABLE;
		goto end;
	}
end:
	return status;
}

enum lttng_rotation_status
lttng_rotation_schedule_size_threshold_set_threshold(struct lttng_rotation_schedule *schedule,
						     uint64_t size_threshold_bytes)
{
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;
	struct lttng_rotation_schedule_size_threshold *size_schedule;

	if (!schedule || size_threshold_bytes == 0 || size_threshold_bytes == -1ULL ||
	    schedule->type != LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	size_schedule = lttng::utils::container_of(schedule,
						   &lttng_rotation_schedule_size_threshold::parent);
	size_schedule->size.bytes = size_threshold_bytes;
	size_schedule->size.set = true;
end:
	return status;
}

struct lttng_rotation_schedule *lttng_rotation_schedule_periodic_create(void)
{
	struct lttng_rotation_schedule_periodic *schedule;

	schedule = zmalloc<lttng_rotation_schedule_periodic>();
	if (!schedule) {
		goto end;
	}

	schedule->parent.type = LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC;
end:
	return &schedule->parent;
}

enum lttng_rotation_status
lttng_rotation_schedule_periodic_get_period(const struct lttng_rotation_schedule *schedule,
					    uint64_t *period_us)
{
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;
	struct lttng_rotation_schedule_periodic *periodic_schedule;

	if (!schedule || !period_us || schedule->type != LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	periodic_schedule =
		lttng::utils::container_of(schedule, &lttng_rotation_schedule_periodic::parent);
	if (periodic_schedule->period.set) {
		*period_us = periodic_schedule->period.us;
	} else {
		status = LTTNG_ROTATION_STATUS_UNAVAILABLE;
		goto end;
	}
end:
	return status;
}

enum lttng_rotation_status
lttng_rotation_schedule_periodic_set_period(struct lttng_rotation_schedule *schedule,
					    uint64_t period_us)
{
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;
	struct lttng_rotation_schedule_periodic *periodic_schedule;

	if (!schedule || period_us == 0 || period_us == -1ULL ||
	    schedule->type != LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	periodic_schedule =
		lttng::utils::container_of(schedule, &lttng_rotation_schedule_periodic::parent);
	periodic_schedule->period.us = period_us;
	periodic_schedule->period.set = true;
end:
	return status;
}

void lttng_rotation_schedule_destroy(struct lttng_rotation_schedule *schedule)
{
	if (!schedule) {
		return;
	}
	free(schedule);
}

void lttng_rotation_schedules_destroy(struct lttng_rotation_schedules *schedules)
{
	unsigned int i;

	if (!schedules) {
		return;
	}

	for (i = 0; i < schedules->count; i++) {
		lttng_rotation_schedule_destroy(schedules->schedules[i]);
	}
	free(schedules);
}

enum lttng_rotation_status
lttng_rotation_schedules_get_count(const struct lttng_rotation_schedules *schedules,
				   unsigned int *count)
{
	enum lttng_rotation_status status = LTTNG_ROTATION_STATUS_OK;

	if (!schedules || !count) {
		status = LTTNG_ROTATION_STATUS_INVALID;
		goto end;
	}

	*count = schedules->count;
end:
	return status;
}

const struct lttng_rotation_schedule *
lttng_rotation_schedules_get_at_index(const struct lttng_rotation_schedules *schedules,
				      unsigned int index)
{
	const struct lttng_rotation_schedule *schedule = NULL;

	if (!schedules || index >= schedules->count) {
		goto end;
	}

	schedule = schedules->schedules[index];
end:
	return schedule;
}

enum lttng_rotation_status
lttng_session_add_rotation_schedule(const char *session_name,
				    const struct lttng_rotation_schedule *schedule)
{
	return lttng_rotation_update_schedule(session_name, schedule, true);
}

enum lttng_rotation_status
lttng_session_remove_rotation_schedule(const char *session_name,
				       const struct lttng_rotation_schedule *schedule)
{
	return lttng_rotation_update_schedule(session_name, schedule, false);
}

int lttng_session_list_rotation_schedules(const char *session_name,
					  struct lttng_rotation_schedules **schedules)
{
	return get_schedules(session_name, schedules);
}
