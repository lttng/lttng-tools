/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRACKER_H
#define LTTNG_TRACKER_H

#include <lttng/constant.h>
#include <lttng/domain.h>
#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>
#include <lttng/session.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Process attribute tracked by a tracker.
 */
enum lttng_process_attr {
	/* Kernel space domain only. */
	LTTNG_PROCESS_ATTR_PROCESS_ID = 0,
	/* Kernel and user space domains. */
	LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID = 1,
	/* Kernel space domain only. */
	LTTNG_PROCESS_ATTR_USER_ID = 2,
	/* Kernel and user space domains. */
	LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID = 3,
	/* Kernel space domain only. */
	LTTNG_PROCESS_ATTR_GROUP_ID = 4,
	/* Kernel and user space domains. */
	LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID = 5,
};

/*
 * Tracking (filtering) policy of a process attribute tracker.
 */
enum lttng_tracking_policy {
	/*
	 * Track all possible process attribute value of a given type
	 * (i.e. no filtering).
	 * This is the default state of a process attribute tracker.
	 */
	LTTNG_TRACKING_POLICY_INCLUDE_ALL = 0,
	/* Exclude all possible process attribute values of a given type. */
	LTTNG_TRACKING_POLICY_EXCLUDE_ALL = 1,
	/* Track a set of specific process attribute values. */
	LTTNG_TRACKING_POLICY_INCLUDE_SET = 2,
};

/*
 * Type of a process attribute value.
 *
 * This allows the use of the matching accessor given the type of a value.
 */
enum lttng_process_attr_value_type {
	LTTNG_PROCESS_ATTR_VALUE_TYPE_INVALID = -1,
	LTTNG_PROCESS_ATTR_VALUE_TYPE_PID = 0,
	LTTNG_PROCESS_ATTR_VALUE_TYPE_UID = 1,
	LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME = 2,
	LTTNG_PROCESS_ATTR_VALUE_TYPE_GID = 3,
	LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME = 4,
};

enum lttng_process_attr_tracker_handle_status {
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_GROUP_NOT_FOUND = -7,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_USER_NOT_FOUND = -6,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID_TRACKING_POLICY = -5,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST = -4,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR = -3,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_COMMUNICATION_ERROR = -2,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID = -1,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK = 0,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_EXISTS = 1,
	LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_MISSING = 2,
};

enum lttng_process_attr_values_status {
	LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID_TYPE = -2,
	LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID = -1,
	LTTNG_PROCESS_ATTR_VALUES_STATUS_OK = 0,
};

/*
 * A process attribute tracker handle.
 *
 * A process attribute tracker is an _inclusion set_ of process
 * attribute values. Tracked processes are allowed to emit events,
 * provided those events are targeted by enabled event rules.
 *
 * An LTTng session is created with a number of process attribute
 * trackers by default. The process attributes that can be tracked vary by
 * domain (see enum lttng_process_attr).
 *
 * Trackers are per-domain (user and kernel space) and allow the filtering
 * of events based on a process's attributes.
 */
struct lttng_process_attr_tracker_handle;

/* A set of process attribute values. */
struct lttng_process_attr_values;

/*
 * Get a handle to one of the process attribute trackers of a session's domain.
 *
 * Returns LTTNG_OK and a process attribute tracker handle on success,
 * or an lttng_error_code on error.
 *
 * The tracker's ownership is transfered to the caller. Use
 * lttng_process_attr_tracker_handle_destroy() to dispose of it.
 */
LTTNG_EXPORT extern enum lttng_error_code
lttng_session_get_tracker_handle(const char *session_name,
				 enum lttng_domain_type domain,
				 enum lttng_process_attr process_attr,
				 struct lttng_process_attr_tracker_handle **out_tracker_handle);

/*
 * Destroy a process attribute tracker handle.
 */
LTTNG_EXPORT extern void
lttng_process_attr_tracker_handle_destroy(struct lttng_process_attr_tracker_handle *tracker_handle);

/*
 * Get the tracking policy of a process attribute tracker.
 *
 * Returns the LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK and the tracking
 * policy of a process attribute tracker on success,
 * LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID on error.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_tracker_handle_get_tracking_policy(
	const struct lttng_process_attr_tracker_handle *tracker_handle,
	enum lttng_tracking_policy *policy);

/*
 * Set the tracking policy of a process attribute tracker.
 *
 * Setting the tracking policy to the current tracking policy has no effect.
 *
 * Returns the LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID on error.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_tracker_handle_set_tracking_policy(
	const struct lttng_process_attr_tracker_handle *tracker_handle,
	enum lttng_tracking_policy policy);

/*
 * Add a numerical PID to the process ID process attribute tracker inclusion
 * set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_process_id_tracker_handle_add_pid(
	const struct lttng_process_attr_tracker_handle *process_id_tracker, pid_t pid);

/*
 * Remove a numerical PID from the process ID process attribute tracker include
 * set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_process_id_tracker_handle_remove_pid(
	const struct lttng_process_attr_tracker_handle *process_id_tracker, pid_t pid);

/*
 * Add a numerical PID to the virtual process ID process attribute tracker
 * inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_process_id_tracker_handle_add_pid(
	const struct lttng_process_attr_tracker_handle *process_id_tracker, pid_t vpid);

/*
 * Remove a numerical PID from the virtual process ID process attribute tracker
 * inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_process_id_tracker_handle_remove_pid(
	const struct lttng_process_attr_tracker_handle *process_id_tracker, pid_t vpid);

/*
 * Add a numerical UID to the user ID process attribute tracker inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_user_id_tracker_handle_add_uid(
	const struct lttng_process_attr_tracker_handle *user_id_tracker, uid_t uid);

/*
 * Remove a numerical UID from the user ID process attribute tracker include
 * set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_user_id_tracker_handle_remove_uid(
	const struct lttng_process_attr_tracker_handle *user_id_tracker, uid_t uid);

/*
 * Add a user name to the user ID process attribute tracker inclusion set.
 *
 * The user name resolution is performed by the session daemon on addition to
 * the user ID inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_user_id_tracker_handle_add_user_name(
	const struct lttng_process_attr_tracker_handle *user_id_tracker, const char *user_name);

/*
 * Remove a user name from the user ID process attribute tracker include
 * set.
 *
 * No name resolution is performed; the user name will be matched against the
 * names in the inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_user_id_tracker_handle_remove_user_name(
	const struct lttng_process_attr_tracker_handle *user_id_tracker, const char *user_name);

/*
 * Add a numerical UID to the virtual user ID process attribute tracker
 * inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_user_id_tracker_handle_add_uid(
	const struct lttng_process_attr_tracker_handle *user_id_tracker, uid_t vuid);

/*
 * Remove a numerical UID from the virtual user ID process attribute tracker
 * inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_user_id_tracker_handle_remove_uid(
	const struct lttng_process_attr_tracker_handle *user_id_tracker, uid_t vuid);

/*
 * Add a user name to the virtual user ID process attribute tracker include
 * set.
 *
 * The user name resolution is performed by the session daemon on addition to
 * the virtual user ID inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_user_id_tracker_handle_add_user_name(
	const struct lttng_process_attr_tracker_handle *user_id_tracker,
	const char *virtual_user_name);

/*
 * Remove a user name from the virtual user ID process attribute tracker
 * inclusion set.
 *
 * No name resolution is performed; the user name will be matched against the
 * names in the inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_user_id_tracker_handle_remove_user_name(
	const struct lttng_process_attr_tracker_handle *user_id_tracker,
	const char *virtual_user_name);

/*
 * Add a numerical GID to the group ID process attribute tracker inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_group_id_tracker_handle_add_gid(
	const struct lttng_process_attr_tracker_handle *group_id_tracker, gid_t gid);

/*
 * Remove a numerical GID from the group ID process attribute tracker include
 * set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_group_id_tracker_handle_remove_gid(
	const struct lttng_process_attr_tracker_handle *group_id_tracker, gid_t gid);

/*
 * Add a group name to the group ID process attribute tracker inclusion set.
 *
 * The group name resolution is performed by the session daemon on addition to
 * the group ID inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_group_id_tracker_handle_add_group_name(
	const struct lttng_process_attr_tracker_handle *group_id_tracker, const char *group_name);

/*
 * Remove a group name from the group ID process attribute tracker include
 * set.
 *
 * No name resolution is performed; the user name will be matched against the
 * names in the inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_group_id_tracker_handle_remove_group_name(
	const struct lttng_process_attr_tracker_handle *group_id_tracker, const char *group_name);

/*
 * Add a numerical GID to the virtual group ID process attribute tracker
 * inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_group_id_tracker_handle_add_gid(
	const struct lttng_process_attr_tracker_handle *group_id_tracker, gid_t vgid);

/*
 * Remove a numerical GID from the virtual group ID process attribute tracker
 * inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_group_id_tracker_handle_remove_gid(
	const struct lttng_process_attr_tracker_handle *group_id_tracker, gid_t vgid);

/*
 * Add a group name to the virtual group ID process attribute tracker include
 * set.
 *
 * The group name resolution is performed by the session daemon on addition to
 * the virtual group ID inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_EXISTS if it was already
 * present in the inclusion set, and
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if an invalid tracker
 * argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_group_id_tracker_handle_add_group_name(
	const struct lttng_process_attr_tracker_handle *group_id_tracker,
	const char *virtual_group_name);

/*
 * Remove a group name from the virtual group ID process attribute tracker
 * inclusion set.
 *
 * No name resolution is performed; the user name will be matched against the
 * names in the inclusion set.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_MISSING if it was not present
 * in the inclusion set, and LTTNG_PROCESS_ATTR_TRACKED_HANDLE_STATUS_INVALID if
 * an invalid tracker argument was provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_virtual_group_id_tracker_handle_remove_group_name(
	const struct lttng_process_attr_tracker_handle *group_id_tracker,
	const char *virtual_group_name);

/*
 * Get the process attribute values that are part of a tracker's inclusion set.
 *
 * The values returned are a snapshot of the values that are part of the
 * tracker's inclusion set at the moment of the invocation; it is not updated
 * as entries are added or removed.
 *
 * The values remain valid until the tracker is destroyed.
 *
 * Returns LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID if the tracker's policy is
 * not LTTNG_POLICY_INCLUDE_SET.
 */
LTTNG_EXPORT extern enum lttng_process_attr_tracker_handle_status
lttng_process_attr_tracker_handle_get_inclusion_set(
	struct lttng_process_attr_tracker_handle *tracker_handle,
	const struct lttng_process_attr_values **values);

/*
 * Get the count of values within a set of process attribute values.
 *
 * Returns LTTNG_PROCESS_ATTR_VALUES_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID if an invalid argument is provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_values_status
lttng_process_attr_values_get_count(const struct lttng_process_attr_values *values,
				    unsigned int *count);

/*
 * Get the type of a process attribute value at a given index.
 *
 * Returns a process attribute value type on success,
 * LTTNG_PROCESS_ATTR_VALUE_TYPE_INVALID if an invalid argument is provided.
 */
LTTNG_EXPORT extern enum lttng_process_attr_value_type
lttng_process_attr_values_get_type_at_index(const struct lttng_process_attr_values *values,
					    unsigned int index);

/*
 * Get a process ID process attribute value.
 *
 * Returns LTTNG_PROCESS_ATTR_VALUES_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID_TYPE if the process attribute value
 * is not a process ID.
 */
LTTNG_EXPORT extern enum lttng_process_attr_values_status
lttng_process_attr_values_get_pid_at_index(const struct lttng_process_attr_values *values,
					   unsigned int index,
					   pid_t *pid);

/*
 * Get a user ID process attribute value.
 *
 * Returns LTTNG_PROCESS_ATTR_VALUES_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID_TYPE if the process attribute value
 * is not a user ID.
 */
LTTNG_EXPORT extern enum lttng_process_attr_values_status
lttng_process_attr_values_get_uid_at_index(const struct lttng_process_attr_values *values,
					   unsigned int index,
					   uid_t *uid);

/*
 * Get a user name process attribute value.
 *
 * Returns LTTNG_PROCESS_ATTR_VALUES_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID_TYPE if the process attribute value
 * is not a user name.
 */
LTTNG_EXPORT extern enum lttng_process_attr_values_status
lttng_process_attr_values_get_user_name_at_index(const struct lttng_process_attr_values *values,
						 unsigned int index,
						 const char **user_name);

/*
 * Get a group ID process attribute value.
 *
 * Returns LTTNG_PROCESS_ATTR_VALUES_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID_TYPE if the process attribute value
 * is not a group ID.
 */
LTTNG_EXPORT extern enum lttng_process_attr_values_status
lttng_process_attr_values_get_gid_at_index(const struct lttng_process_attr_values *values,
					   unsigned int index,
					   gid_t *gid);

/*
 * Get a group name process attribute value.
 *
 * Returns LTTNG_PROCESS_ATTR_VALUES_STATUS_OK on success,
 * LTTNG_PROCESS_ATTR_VALUES_STATUS_INVALID_TYPE if the process attribute value
 * is not a group name.
 */
LTTNG_EXPORT extern enum lttng_process_attr_values_status
lttng_process_attr_values_get_group_name_at_index(const struct lttng_process_attr_values *values,
						  unsigned int index,
						  const char **group_name);

/* The following entry points are deprecated. */

/*
 * Deprecated: see `lttng_process_attr_tracker_handle_get_inclusion_set` and
 * `lttng_process_tracker_handle_get_tracking_policy`.
 *
 * List tracked PIDs.
 *
 * `enabled` indicates whether or not the PID tracker is enabled.
 *
 * `pids` is set to an allocated array of PIDs currently being tracked. On
 * success, `pids` must be freed by the caller.
 *
 * `nr_pids` is set to the number of entries contained in the `pids` array.
 *
 * Returns 0 on success, else a negative LTTng error code.
 */
LTTNG_EXPORT extern int
lttng_list_tracker_pids(struct lttng_handle *handle, int *enabled, int32_t **pids, size_t *nr_pids);

/*
 * Deprecated: see `lttng_process_attr_process_id_tracker_handle_add_pid`.
 *
 * Add PID to session tracker.
 *
 * A pid argument >= 0 adds the PID to the session's PID tracker.
 * A pid argument of -1 means "track all PIDs".
 *
 * Note on 'real' PIDs vs 'virtual' VPIDs:
 *   - With the user space domain specified, this function will add a VPID
 *     value to the virtual process ID process attribute tracker's inclusion
 *     set.
 *   - With the kernel space domain specified, this function will add a PID
 *     value to the process ID process attribute tracker's inclusion set.
 *
 * Returns 0 on success, else a negative LTTng error code.
 */
LTTNG_EXPORT extern int lttng_track_pid(struct lttng_handle *handle, int pid);

/*
 * Deprecated: see `lttng_process_attr_process_id_tracker_handle_remove_pid`.
 *
 * Remove PID from session tracker.
 *
 * A pid argument >= 0 removes the PID from the session's PID tracker.
 * A pid argument of -1 means "untrack all PIDs".
 *
 * Note on 'real' PIDs vs 'virtual' VPIDs:
 *   - With the user space domain specified, this function will remove a VPID
 *     value from the virtual process ID process attribute tracker's inclusion
 *     set.
 *   - With the kernel space domain specified, this function will remove a PID
 *     value from the process ID process attribute tracker's inclusion set.
 *
 * Returns 0 on success, else a negative LTTng error code.
 */
LTTNG_EXPORT extern int lttng_untrack_pid(struct lttng_handle *handle, int pid);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_TRACKER_H */
