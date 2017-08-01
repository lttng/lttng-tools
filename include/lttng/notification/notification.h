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
 * Get a notification's condition.
 *
 * The notification retains the ownership of both the condition and evaluation
 * objects. Hence, it is not valid to access those objects after the destruction
 * of their associated notification.
 *
 * The caller should check the condition's type in order to use the appropriate
 * specialized functions to access the condition's properties.
 *
 * Returns an lttng_condition object on success, NULL on error.
 */
extern const struct lttng_condition *lttng_notification_get_condition(
		struct lttng_notification *notification);

/*
 * Get a notification's condition's evaluation.
 *
 * The notification retains the ownership of the evaluation object. Hence, it is
 * not valid to access that object after the destruction of its associated
 * notification.
 *
 * The caller should check the evaluation's type in order to use the appropriate
 * specialized functions to access the evaluation's properties.
 *
 * Returns an lttng_evaluation object on success, NULL on error.
 */
extern const struct lttng_evaluation *lttng_notification_get_evaluation(
		struct lttng_notification *notification);

/*
 * Destroys (frees) a notification. The notification's condition and evaluation
 * are destroyed as a side-effect.
 */
extern void lttng_notification_destroy(struct lttng_notification *notification);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_NOTIFICATION_H */
