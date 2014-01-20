/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
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

#include "session.h"

/*
 * Lookup a session within the given hash table and session id. RCU read side
 * lock MUST be acquired before calling this and as long as the caller has a
 * reference to the object.
 *
 * Return session or NULL if not found.
 */
struct relay_session *session_find_by_id(struct lttng_ht *ht, uint64_t id)
{
	struct relay_session *session = NULL;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	assert(ht);

	lttng_ht_lookup(ht, (void *)((unsigned long) id), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (!node) {
		goto end;
	}
	session = caa_container_of(node, struct relay_session, session_n);

end:
	return session;
}
