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

#ifndef _JUL_H
#define _JUL_H

#include <common/hashtable/hashtable.h>
#include <lttng/lttng.h>

/*
 * Java Util Logging event representation.
 */
struct jul_event {
	/*
	 * Name of the event which is directly mapped to a Logger object name in
	 * the JUL API.
	 */
	char name[LTTNG_SYMBOL_NAME_LEN];

	/*
	 * Tells if the event is enabled or not on the JUL Agent.
	 */
	unsigned int enabled:1;

	/*
	 * Hash table nodes of the JUL domain. Indexed by name string.
	 */
	struct lttng_ht_node_str node;
};

/*
 * Top level data structure in a UST session containing JUL event name created
 * for it.
 */
struct jul_domain {
	/*
	 * Contains JUL event indexed by name.
	 */
	struct lttng_ht *events;
};

int jul_init_domain(struct jul_domain *dom);
struct jul_event *jul_create_event(const char *name);
void jul_add_event(struct jul_event *event, struct jul_domain *dom);
struct jul_event *jul_find_by_name(const char *name, struct jul_domain *dom);
void jul_delete_event(struct jul_event *event, struct jul_domain *dom);
void jul_destroy_event(struct jul_event *event);
void jul_destroy_domain(struct jul_domain *dom);

#endif /* _JUL_H */
