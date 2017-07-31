/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef LTTNG_ACTION_H
#define LTTNG_ACTION_H

struct lttng_action;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_action_type {
	LTTNG_ACTION_TYPE_UNKNOWN = -1,
	LTTNG_ACTION_TYPE_NOTIFY = 0,
};

/*
 * Get the type of an action.
 *
 * Returns the type of an action on success, LTTNG_ACTION_TYPE_UNKNOWN on error.
 */
extern enum lttng_action_type lttng_action_get_type(
		struct lttng_action *action);

/*
 * Destroy (frees) an action object.
 */
extern void lttng_action_destroy(struct lttng_action *action);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_H */
