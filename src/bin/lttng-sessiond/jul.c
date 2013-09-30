/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
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

#define _GNU_SOURCE
#include <assert.h>

#include <common/common.h>

#include "jul.h"
#include "utils.h"

/*
 * URCU intermediate call to complete destroy a JUL event.
 */
static void destroy_event_jul_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_str *node =
		caa_container_of(head, struct lttng_ht_node_str, head);
	struct jul_event *event =
		caa_container_of(node, struct jul_event, node);

	free(event);
}

/*
 * Initialize an already allocated JUL domain object.
 *
 * Return 0 on success or else a negative errno value.
 */
int jul_init_domain(struct jul_domain *dom)
{
	int ret;

	assert(dom);

	dom->events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!dom->events) {
		ret = -ENOMEM;
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * Create a newly allocated JUL event data structure. If name is valid, it's
 * copied into the created event.
 *
 * Return a new object else NULL on error.
 */
struct jul_event *jul_create_event(const char *name)
{
	struct jul_event *event;

	DBG3("JUL create new event with name %s", name);

	event = zmalloc(sizeof(*event));
	if (!event) {
		goto error;
	}

	if (name) {
		strncpy(event->name, name, sizeof(event->name));
		event->name[sizeof(event->name) - 1] = '\0';
	}

error:
	return event;
}

/*
 * Unique add of a JUL event to a given domain.
 */
void jul_add_event(struct jul_event *event, struct jul_domain *dom)
{
	assert(event);
	assert(dom);
	assert(dom->events);

	DBG3("JUL adding event %s to domain", event->name);

	lttng_ht_add_unique_str(dom->events, &event->node);
}

/*
 * Find a JUL event in the given domain using name.
 *
 * RCU read side lock MUST be acquired.
 *
 * Return object if found else NULL.
 */
struct jul_event *jul_find_by_name(const char *name, struct jul_domain *dom)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	assert(name);
	assert(dom);
	assert(dom->events);

	lttng_ht_lookup(dom->events, (void *)name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		goto error;
	}

	DBG3("JUL found by name %s in domain.", name);
	return caa_container_of(node, struct jul_event, node);

error:
	DBG3("JUL NOT found by name %s in domain.", name);
	return NULL;
}

/*
 * Delete JUL event from given domain. Events hash table MUST be initialized.
 */
void jul_delete_event(struct jul_event *event, struct jul_domain *dom)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(event);
	assert(dom);
	assert(dom->events);

	DBG3("JUL deleting event %s from domain", event->name);

	iter.iter.node = &event->node.node;
	rcu_read_lock();
	ret = lttng_ht_del(dom->events, &iter);
	rcu_read_unlock();
	assert(!ret);
}

/*
 * Free given JUl event. After this call, the pointer is not usable anymore.
 */
void jul_destroy_event(struct jul_event *event)
{
	assert(event);

	free(event);
}

/*
 * Destroy a JUL domain completely. Note that the given pointer is NOT freed
 * thus a reference can be passed to this function.
 */
void jul_destroy_domain(struct jul_domain *dom)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	assert(dom);

	DBG3("JUL destroy domain");

	/*
	 * Just ignore if no events hash table exists. This is possible if for
	 * instance a JUL domain object was allocated but not initialized.
	 */
	if (!dom->events) {
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(dom->events->ht, &iter.iter, node, node) {
		int ret;

		ret = lttng_ht_del(dom->events, &iter);
		assert(!ret);
		call_rcu(&node->head, destroy_event_jul_rcu);
	}
	rcu_read_unlock();

	ht_cleanup_push(dom->events);
}
