/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "thread.h"
#include <urcu/list.h>
#include <urcu/ref.h>
#include <pthread.h>
#include <common/macros.h>
#include <common/error.h>
#include <common/defaults.h>

static struct thread_list {
	struct cds_list_head head;
	pthread_mutex_t lock;
} thread_list = {
	.head = CDS_LIST_HEAD_INIT(thread_list.head),
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

struct lttng_thread {
	struct urcu_ref ref;
	struct cds_list_head node;
	pthread_t thread;
	const char *name;
	/* Main thread function */
	lttng_thread_entry_point entry;
	/*
	 * Thread-specific shutdown method. Allows threads to implement their
	 * own shutdown mechanism as some of them use a structured message
	 * passed through a command queue and some rely on a dedicated "quit"
	 * pipe.
	 */
	lttng_thread_shutdown_cb shutdown;
	lttng_thread_cleanup_cb cleanup;
	/* Thread implementation-specific data. */
	void *data;
};

static
void lttng_thread_destroy(struct lttng_thread *thread)
{
	if (thread->cleanup) {
		thread->cleanup(thread->data);
	}
	free(thread);
}

static
void lttng_thread_release(struct urcu_ref *ref)
{
	lttng_thread_destroy(container_of(ref, struct lttng_thread, ref));
}

static
void *launch_thread(void *data)
{
	void *ret;
	struct lttng_thread *thread = (struct lttng_thread *) data;

	logger_set_thread_name(thread->name, true);
	DBG("Entering thread entry point");
	ret = thread->entry(thread->data);
	DBG("Thread entry point has returned");
	return ret;
}

struct lttng_thread *lttng_thread_create(const char *name,
		lttng_thread_entry_point entry,
		lttng_thread_shutdown_cb shutdown,
		lttng_thread_cleanup_cb cleanup,
		void *thread_data)
{
	int ret;
	struct lttng_thread *thread;

	thread = zmalloc(sizeof(*thread));
	if (!thread) {
		goto error_alloc;
	}

	urcu_ref_init(&thread->ref);
	CDS_INIT_LIST_HEAD(&thread->node);
	/*
	 * Thread names are assumed to be statically allocated strings.
	 * It is unnecessary to copy this attribute.
	 */
	thread->name = name;
	thread->entry = entry;
	thread->shutdown = shutdown;
	thread->cleanup = cleanup;
	thread->data = thread_data;

	pthread_mutex_lock(&thread_list.lock);
	/*
	 * Add the thread at the head of the list to shutdown threads in the
	 * opposite order of their creation. A reference is taken for the
	 * thread list which will be released on shutdown of the thread.
	 */
	cds_list_add(&thread->node, &thread_list.head);
	(void) lttng_thread_get(thread);

	ret = pthread_create(&thread->thread, default_pthread_attr(),
			launch_thread, thread);
	if (ret) {
		PERROR("Failed to create \"%s\" thread", thread->name);
		goto error_pthread_create;
	}

	pthread_mutex_unlock(&thread_list.lock);
	return thread;

error_pthread_create:
	cds_list_del(&thread->node);
	/* Release list reference. */
	lttng_thread_put(thread);
	pthread_mutex_unlock(&thread_list.lock);
	/* Release initial reference. */
	lttng_thread_put(thread);
error_alloc:
	return NULL;
}

bool lttng_thread_get(struct lttng_thread *thread)
{
	return urcu_ref_get_unless_zero(&thread->ref);
}

void lttng_thread_put(struct lttng_thread *thread)
{
	if (!thread) {
		return;
	}
	assert(thread->ref.refcount);
	urcu_ref_put(&thread->ref, lttng_thread_release);
}

const char *lttng_thread_get_name(const struct lttng_thread *thread)
{
	return thread->name;
}

static
bool _lttng_thread_shutdown(struct lttng_thread *thread)
{
	int ret;
	void *status;
	bool result = true;

	DBG("Shutting down \"%s\" thread", thread->name);
	if (thread->shutdown) {
		result = thread->shutdown(thread->data);
		if (!result) {
			result = false;
			goto end;
		}
	}

	ret = pthread_join(thread->thread, &status);
	if (ret) {
		PERROR("Failed to join \"%s\" thread", thread->name);
		result = false;
		goto end;
	}
	DBG("Joined thread \"%s\"", thread->name);
end:
	return result;
}

bool lttng_thread_shutdown(struct lttng_thread *thread)
{
	const bool result = _lttng_thread_shutdown(thread);

	if (result) {
		/* Release the list's reference to the thread. */
		pthread_mutex_lock(&thread_list.lock);
		cds_list_del(&thread->node);
		lttng_thread_put(thread);
		pthread_mutex_unlock(&thread_list.lock);
	}
	return result;
}

void lttng_thread_list_shutdown_orphans(void)
{
	struct lttng_thread *thread, *tmp;

	pthread_mutex_lock(&thread_list.lock);
	cds_list_for_each_entry_safe(thread, tmp, &thread_list.head, node) {
		bool result;
		const long ref = uatomic_read(&thread->ref.refcount);

		if (ref != 1) {
			/*
			 * Other external references to the thread exist, skip.
			 */
			continue;
		}

		result = _lttng_thread_shutdown(thread);
		if (!result) {
			ERR("Failed to shutdown thread \"%s\"", thread->name);
		}
	}
	pthread_mutex_unlock(&thread_list.lock);
}
