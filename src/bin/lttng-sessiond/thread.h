/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdbool.h>

#ifndef THREAD_H
#define THREAD_H

struct lttng_thread;

/* Main function of the new thread. */
typedef void *(*lttng_thread_entry_point)(void *);

/* Callback invoked to initiate the shutdown a thread. */
typedef bool (*lttng_thread_shutdown_cb)(void *);

/*
 * Callback invoked to clean-up the thread data.
 * Invoked when the thread is destroyed to ensure there is no
 * race between a use by the "thread shutdown callback" and
 * a use by the thread itself.
 */
typedef void (*lttng_thread_cleanup_cb)(void *);

/*
 * Returns a reference to the newly-created thread.
 * The shutdown and cleanup callbacks are optional.
 */
struct lttng_thread *lttng_thread_create(const char *name,
		lttng_thread_entry_point entry,
		lttng_thread_shutdown_cb shutdown,
		lttng_thread_cleanup_cb cleanup,
		void *thread_data);

bool lttng_thread_get(struct lttng_thread *thread);
void lttng_thread_put(struct lttng_thread *thread);

const char *lttng_thread_get_name(const struct lttng_thread *thread);

/*
 * Explicitly shutdown a thread. This function returns once the
 * thread has returned and been joined.
 *
 * It is invalid to call this function more than once on a thread.
 *
 * Returns true on success, false on error.
 */
bool lttng_thread_shutdown(struct lttng_thread *thread);

/*
 * Shutdown all orphaned threads (threads to which no external reference
 * exist).
 *
 * Returns once all orphaned threads have been joined.
 */
void lttng_thread_list_shutdown_orphans(void);

#endif /* THREAD_H */
