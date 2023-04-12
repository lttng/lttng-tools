/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ROTATION_H
#define LTTNG_ROTATION_H

#include <lttng/location.h>
#include <lttng/lttng-export.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return codes for lttng_rotation_handle_get_state()
 */
enum lttng_rotation_state {
	/*
	 * Session has not been rotated.
	 */
	LTTNG_ROTATION_STATE_NO_ROTATION = 0,
	/*
	 * Rotation is ongoing, but has not been completed yet.
	 */
	LTTNG_ROTATION_STATE_ONGOING = 1,
	/*
	 * Rotation has been completed and the resulting chunk
	 * can now safely be read.
	 */
	LTTNG_ROTATION_STATE_COMPLETED = 2,
	/*
	 * The rotation has expired.
	 *
	 * The information associated with a given rotation is eventually
	 * purged by the session daemon. In such a case, the attributes of
	 * the rotation, such as its path, may no longer be available.
	 *
	 * Note that this state does not guarantee the the rotation was
	 * completed successfully.
	 */
	LTTNG_ROTATION_STATE_EXPIRED = 3,
	/*
	 * The rotation could not be completed due to an error.
	 */
	LTTNG_ROTATION_STATE_ERROR = -1,
};

enum lttng_rotation_status {
	LTTNG_ROTATION_STATUS_OK = 0,
	/* Information not available. */
	LTTNG_ROTATION_STATUS_UNAVAILABLE = 1,
	/* Generic error. */
	LTTNG_ROTATION_STATUS_ERROR = -1,
	/* Invalid parameters provided. */
	LTTNG_ROTATION_STATUS_INVALID = -2,
	/* A schedule of this type is already set. */
	LTTNG_ROTATION_STATUS_SCHEDULE_ALREADY_SET = -3,
	/* No such rotation schedule set. */
	LTTNG_ROTATION_STATUS_SCHEDULE_NOT_SET = -3,
};

enum lttng_rotation_schedule_type {
	LTTNG_ROTATION_SCHEDULE_TYPE_UNKNOWN = -1,
	LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD = 0,
	LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC = 1,
};

/*
 * Descriptor of an immediate session rotation to be performed as soon as
 * possible by the tracers.
 */
struct lttng_rotation_immediate_descriptor;

/*
 * Session rotation schedule to add to a session.
 */
struct lttng_rotation_schedule;

/*
 * A set of lttng_rotation_schedule objects.
 */
struct lttng_rotation_schedules;

/*
 * Handle used to represent a specific rotation.
 */
struct lttng_rotation_handle;

/*
 * lttng rotate session handle functions.
 */

/*
 * Get the current state of the rotation referenced by the handle.
 *
 * This will issue a request to the session daemon on every call. Hence,
 * the result of this call may change over time.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_rotation_handle_get_state(struct lttng_rotation_handle *rotation_handle,
				enum lttng_rotation_state *rotation_state);

/*
 * Get the location of the rotation's resulting archive.
 *
 * The rotation must be completed in order for this call to succeed.
 * The location returned remains owned by the rotation handle.
 *
 * Note that location will not be set in case of error, or if the session
 * rotation handle has expired.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_rotation_handle_get_archive_location(struct lttng_rotation_handle *rotation_handle,
					   const struct lttng_trace_archive_location **location);

/*
 * Destroy an lttng_rotate_session handle.
 */
LTTNG_EXPORT extern void
lttng_rotation_handle_destroy(struct lttng_rotation_handle *rotation_handle);

/*
 * Rotate the output folder of the session.
 *
 * On success, handle is allocated and can be used to monitor the progress
 * of the rotation with lttng_rotation_get_state(). The handle must be freed
 * by the caller with lttng_rotation_handle_destroy().
 *
 * Passing NULL as the immediate rotation descriptor results in the default
 * options being used.
 *
 * Return 0 if the rotate action was successfully launched or a negative
 * LTTng error code on error.
 */
LTTNG_EXPORT extern int lttng_rotate_session(const char *session_name,
					     struct lttng_rotation_immediate_descriptor *descriptor,
					     struct lttng_rotation_handle **rotation_handle);

/*
 * Get the type of a rotation schedule object.
 */
LTTNG_EXPORT extern enum lttng_rotation_schedule_type
lttng_rotation_schedule_get_type(const struct lttng_rotation_schedule *schedule);

/*
 * Return a newly allocated size-based session rotation schedule or NULL on
 * error.
 */
LTTNG_EXPORT extern struct lttng_rotation_schedule *
lttng_rotation_schedule_size_threshold_create(void);

/*
 * Get a session rotation schedule's size threshold.
 *
 * Returns LTTNG_ROTATION_STATUS_OK on success.
 * LTTNG_ROTATION_STATUS_UNAVAILABLE is returned if the value is unset.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_rotation_schedule_size_threshold_get_threshold(const struct lttng_rotation_schedule *schedule,
						     uint64_t *size_threshold_bytes);

/*
 * Set a session rotation schedule's size threshold.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_rotation_schedule_size_threshold_set_threshold(struct lttng_rotation_schedule *schedule,
						     uint64_t size_threshold_bytes);

/*
 * Return a newly allocated periodic session rotation schedule or NULL on
 * error.
 */
LTTNG_EXPORT extern struct lttng_rotation_schedule *lttng_rotation_schedule_periodic_create(void);

/*
 * Get a time-based session rotation schedule's period.
 *
 * Returns LTTNG_ROTATION_STATUS_OK on success.
 * LTTNG_ROTATION_STATUS_UNAVAILABLE is returned if the value is unset.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_rotation_schedule_periodic_get_period(const struct lttng_rotation_schedule *schedule,
					    uint64_t *period_us);

/*
 * Set a time-based session rotation schedule's period.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_rotation_schedule_periodic_set_period(struct lttng_rotation_schedule *schedule,
					    uint64_t period_us);

/*
 * Destroy a rotation schedule.
 */
LTTNG_EXPORT extern void lttng_rotation_schedule_destroy(struct lttng_rotation_schedule *schedule);

/*
 * Destroy a set of rotation schedules. Pointers to any schedule contained
 * in this set become invalid after this call.
 */
LTTNG_EXPORT extern void
lttng_rotation_schedules_destroy(struct lttng_rotation_schedules *schedules);

/*
 * Get the number of schedules in a schedule set.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_rotation_schedules_get_count(const struct lttng_rotation_schedules *schedules,
				   unsigned int *count);

/*
 * Get a schedule from the set at a given index.
 *
 * Note that the set maintains the ownership of the returned schedule.
 * It must not be destroyed by the user, nor should it be held beyond
 * the lifetime of the schedules set.
 *
 * Returns a rotation schedule, or NULL on error.
 */
LTTNG_EXPORT extern const struct lttng_rotation_schedule *
lttng_rotation_schedules_get_at_index(const struct lttng_rotation_schedules *schedules,
				      unsigned int index);

/*
 * Add a session rotation schedule to a session.
 *
 * Note that the current implementation currently limits the rotation schedules
 * associated to a given session to one per type.
 *
 * Returns LTTNG_ROTATION_STATUS_OK on success,
 * LTTNG_ROTATION_STATUS_SCHEDULE_ALREADY_SET if a rotation of the same type
 * is already set.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_session_add_rotation_schedule(const char *session_name,
				    const struct lttng_rotation_schedule *schedule);

/*
 * Remove a session rotation schedule from a session.
 *
 * Returns LTTNG_ROTATION_STATUS_OK on success,
 * LTTNG_ROTATION_STATUS_SCHEDULE_INVALID if the provided schedule is
 * not set.
 */
LTTNG_EXPORT extern enum lttng_rotation_status
lttng_session_remove_rotation_schedule(const char *session_name,
				       const struct lttng_rotation_schedule *schedule);

/*
 * Get the rotation schedules associated with a given session.
 *
 * Returns LTTNG_OK on success, or a negative lttng error code on error.
 */
LTTNG_EXPORT extern int
lttng_session_list_rotation_schedules(const char *session_name,
				      struct lttng_rotation_schedules **schedules);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ROTATION_H */
