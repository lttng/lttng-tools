/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_NOTIFICATION_H
#define LTTNG_NOTIFICATION_H

#include <lttng/lttng-export.h>

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
LTTNG_EXPORT extern const struct lttng_condition *
lttng_notification_get_condition(struct lttng_notification *notification);

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
LTTNG_EXPORT extern const struct lttng_evaluation *
lttng_notification_get_evaluation(struct lttng_notification *notification);

/*
 * Get a notification's origin trigger.
 *
 * The notification retains the ownership of the trigger object. Hence, it is
 * not valid to access that object after the destruction of its associated
 * notification.
 *
 * Returns an lttng_trigger object on success, NULL on error.
 */
LTTNG_EXPORT extern const struct lttng_trigger *
lttng_notification_get_trigger(struct lttng_notification *notification);

/*
 * Destroys (frees) a notification. The notification's condition and evaluation
 * are destroyed as a side-effect.
 */
LTTNG_EXPORT extern void lttng_notification_destroy(struct lttng_notification *notification);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_NOTIFICATION_H */
