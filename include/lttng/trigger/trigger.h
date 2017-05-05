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

#ifndef LTTNG_TRIGGER_H
#define LTTNG_TRIGGER_H

struct lttng_action;
struct lttng_condition;
struct lttng_trigger;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_register_trigger_status {
	LTTNG_REGISTER_TRIGGER_STATUS_OK = 0,
	LTTNG_REGISTER_TRIGGER_STATUS_INVALID = -1,
};

/* The caller retains the ownership of both condition and action. */
extern struct lttng_trigger *lttng_trigger_create(
		struct lttng_condition *condition, struct lttng_action *action);

extern struct lttng_condition *lttng_trigger_get_condition(
		struct lttng_trigger *trigger);

extern struct lttng_action *lttng_trigger_get_action(
		struct lttng_trigger *trigger);

extern void lttng_trigger_destroy(struct lttng_trigger *trigger);

extern int lttng_register_trigger(struct lttng_trigger *trigger);

extern int lttng_unregister_trigger(struct lttng_trigger *trigger);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_TRIGGER_H */
