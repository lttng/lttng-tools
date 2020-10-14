/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _EVENT_NOTIFIER_ERROR_ACCOUNTING_H
#define _EVENT_NOTIFIER_ERROR_ACCOUNTING_H

#include <stdint.h>

#include <lttng/trigger/trigger.h>

#include "ust-app.h"

enum event_notifier_error_accounting_status {
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE,
	EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD,
};

enum event_notifier_error_accounting_status
event_notifier_error_accounting_init(uint64_t nb_bucket);

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_kernel(
		int kernel_event_notifier_group_fd);

#ifdef HAVE_LIBLTTNG_UST_CTL
enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_app(struct ust_app *app);

enum event_notifier_error_accounting_status
event_notifier_error_accounting_unregister_app(struct ust_app *app);
#else /* HAVE_LIBLTTNG_UST_CTL */
static inline
enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_app(struct ust_app *app)
{
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

static inline
enum event_notifier_error_accounting_status
event_notifier_error_accounting_unregister_app(struct ust_app *app)
{
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_event_notifier(
		const struct lttng_trigger *trigger,
		uint64_t *error_counter_index);

enum event_notifier_error_accounting_status
event_notifier_error_accounting_get_count(
		const struct lttng_trigger *trigger,
		uint64_t *count);

void event_notifier_error_accounting_unregister_event_notifier(
		const struct lttng_trigger *trigger);

void event_notifier_error_accounting_fini(void);

#endif /* _EVENT_NOTIFIER_ERROR_ACCOUNTING_H */
