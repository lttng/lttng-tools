/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _EVENT_NOTIFIER_ERROR_ACCOUNTING_H
#define _EVENT_NOTIFIER_ERROR_ACCOUNTING_H

#include "ust-app.hpp"

#include <lttng/trigger/trigger.h>

#include <stdint.h>

enum event_notifier_error_accounting_status {
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_UNSUPPORTED,
};

/*
 * Initialize the event notifier error accounting system.
 * `buffer_size_kernel` and `buffer_size_ust` represent the number of buckets
 * to be allocated for each domain.
 */
enum event_notifier_error_accounting_status
event_notifier_error_accounting_init(uint64_t buffer_size_kernel, uint64_t buffer_size_ust);

/*
 * Register the kernel event notifier group.
 * This allocates the counter object on the kernel side.
 */
enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_kernel(int kernel_event_notifier_group_fd);

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Register a UST application.
 *
 * This reuses (or creates) the counter object of the app UID.
 */
enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_app(struct ust_app *app);

/*
 * Unregister a UST application.
 */
enum event_notifier_error_accounting_status
event_notifier_error_accounting_unregister_app(struct ust_app *app);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_app(struct ust_app *app __attribute__((unused)))
{
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

static inline enum event_notifier_error_accounting_status
event_notifier_error_accounting_unregister_app(struct ust_app *app __attribute__((unused)))
{
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

/*
 * Allocates, reserves and returns the error counter index for that trigger.
 */
enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_event_notifier(const struct lttng_trigger *trigger,
							uint64_t *error_counter_index);

enum event_notifier_error_accounting_status
event_notifier_error_accounting_get_count(const struct lttng_trigger *trigger, uint64_t *count);

void event_notifier_error_accounting_unregister_event_notifier(const struct lttng_trigger *trigger);

void event_notifier_error_accounting_fini(void);

#endif /* _EVENT_NOTIFIER_ERROR_ACCOUNTING_H */
