/*
 * Copyright (C) 2014 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef LOAD_SESSION_THREAD_H
#define LOAD_SESSION_THREAD_H

#include <semaphore.h>

/* Data passed to the thread. */
struct load_session_thread_data {
	/* Flag if the sem_init() has been done successfully on the sem. */
	unsigned int sem_initialized:1;

	/*
	 * The load session thread waits on that semaphore which the client thread
	 * will do a sem_post() to unblock it.
	 */
	sem_t message_thread_ready;

	/* Path where the sessions are located. */
	const char *path;
};

void *thread_load_session(void *data);

int load_session_init_data(struct load_session_thread_data **data);
void load_session_destroy_data(struct load_session_thread_data *data);

#endif /* LOAD_SESSION_THREAD_H */
