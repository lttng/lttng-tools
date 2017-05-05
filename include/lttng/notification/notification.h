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

#ifndef LTTNG_NOTIFICATION_H
#define LTTNG_NOTIFICATION_H

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_condition;
struct lttng_evaluation;
struct lttng_notification;

/*
 * The notification retains ownership of both the condition and evaluation.
 * Destroying the notification will also destroy the notification and evaluation
 * objects.
 */
extern const struct lttng_condition *lttng_notification_get_condition(
		struct lttng_notification *notification);

extern const struct lttng_evaluation *lttng_notification_get_evaluation(
		struct lttng_notification *notification);

extern void lttng_notification_destroy(struct lttng_notification *notification);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_NOTIFICATION_H */
