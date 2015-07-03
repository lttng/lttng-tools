/*
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_SESSION_H
#define LTTNG_SESSION_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Basic session information.
 *
 * The "enabled" field is only used when listing the sessions which indicate if
 * it's started or not.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_SESSION_PADDING1             12
struct lttng_session {
	char name[LTTNG_NAME_MAX];
	/* The path where traces are written */
	char path[PATH_MAX];
	uint32_t enabled;	/* enabled/started: 1, disabled/stopped: 0 */
	uint32_t snapshot_mode;
	unsigned int live_timer_interval;	/* usec */

	char padding[LTTNG_SESSION_PADDING1];
};

/*
 * Create a tracing session using a name and an optional URL.
 *
 * If _url_ is NULL, no consumer is created for the session. The name can't be
 * NULL here.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_create_session(const char *name, const char *url);

/*
 * Create a tracing session that will exclusively be used for snapshot meaning
 * the session will be in no output mode and every channel enabled for that
 * session will be set in overwrite mode and in mmap output since splice is not
 * supported.
 *
 * Name can't be NULL. If an url is given, it will be used to create a default
 * snapshot output using it as a destination. If NULL, no output will be
 * defined and an add-output call will be needed.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_create_session_snapshot(const char *name,
		const char *snapshot_url);

/*
 * Create a session exclusively used for live reading.
 *
 * In this mode, the switch-timer parameter is forced for each UST channel, a
 * live-switch-timer is enabled for kernel channels, manually setting
 * switch-timer is forbidden. Synchronization beacons are sent to the relayd,
 * indexes are sent and metadata is checked for each packet.
 *
 * Name can't be NULL. If no URL is given, the default is to send the data to
 * net://127.0.0.1. The timer_interval is in usec and by default set to 1000000
 * (1 second).
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_create_session_live(const char *name, const char *url,
		unsigned int timer_interval);

/*
 * Destroy a tracing session.
 *
 * The session will not be usable, tracing will be stopped thus buffers will be
 * flushed.
 *
 * This call will wait for data availability for each domain of the session,
 * which can take an arbitrary amount of time. However, when returning the
 * tracing data is guaranteed to be ready to be read and analyzed.
 *
 * lttng_destroy_session_no_wait() may be used if such a guarantee is not
 * needed.
 *
 * The name can't be NULL here.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_destroy_session(const char *name);

/*
 * Behaves exactly like lttng_destroy_session but does not wait for data
 * availability.
 */
extern int lttng_destroy_session_no_wait(const char *name);

/*
 * List all the tracing sessions.
 *
 * Return the size (number of entries) of the "lttng_session" array. Caller
 * must free sessions. On error, a negative LTTng error code is returned.
 */
extern int lttng_list_sessions(struct lttng_session **sessions);

/*
 * Set the shared memory path for a session.
 *
 * Sets the (optional) file system path where shared memory buffers will
 * be created for the session. This is useful for buffer extraction on
 * crash, when used with filesystems like pramfs.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_set_session_shm_path(const char *session_name,
		const char *shm_path);

/*
 * Add PID to session tracker.
 *
 * A pid argument >= 0 adds the PID to the session tracker.
 * A pid argument of -1 means "track all PIDs".
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_track_pid(struct lttng_handle *handle, int pid);

/*
 * Remove PID from session tracker.
 *
 * A pid argument >= 0 removes the PID from the session tracker.
 * A pid argument of -1 means "untrack all PIDs".
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_untrack_pid(struct lttng_handle *handle, int pid);

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
extern int lttng_list_tracker_pids(struct lttng_handle *handle,
		int *enabled, int32_t **pids, size_t *nr_pids);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_SESSION_H */
