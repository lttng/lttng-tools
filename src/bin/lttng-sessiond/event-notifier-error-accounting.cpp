/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-notifier-error-accounting-kernel.hpp"
#include "event-notifier-error-accounting-ust.hpp"
#include "event-notifier-error-accounting.hpp"

#include <lttng/trigger/trigger-internal.hpp>

#include <stdlib.h>

namespace {
namespace modules_eea = lttng::sessiond::modules::event_notifier_error_accounting;
namespace ust_eea = lttng::sessiond::ust::event_notifier_error_accounting;
} /* namespace */

enum event_notifier_error_accounting_status
event_notifier_error_accounting_init(uint64_t buffer_size_kernel, uint64_t buffer_size_ust)
{
	const auto kernel_status = modules_eea::init(buffer_size_kernel);
	if (kernel_status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		return kernel_status;
	}

	const auto ust_status = ust_eea::init(buffer_size_ust);
	if (ust_status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		modules_eea::fini();
		return ust_status;
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

void event_notifier_error_accounting_fini()
{
	ust_eea::fini();
	modules_eea::fini();
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_kernel_event_notifier_group(
	int kernel_event_notifier_group_fd)
{
	return modules_eea::register_kernel_event_notifier_group(kernel_event_notifier_group_fd);
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_event_notifier(const struct lttng_trigger *trigger,
							uint64_t *error_counter_index)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		return modules_eea::register_event_notifier(trigger, error_counter_index);
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		return ust_eea::register_event_notifier(trigger, error_counter_index);
	default:
		abort();
	}
}

void event_notifier_error_accounting_unregister_event_notifier(const struct lttng_trigger *trigger)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		modules_eea::unregister_event_notifier(trigger);
		return;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		ust_eea::unregister_event_notifier(trigger);
		return;
	default:
		abort();
	}
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_get_error_count(const struct lttng_trigger *trigger,
						uint64_t *count)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		return modules_eea::get_event_notifier_error_count(trigger, count);
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		return ust_eea::get_event_notifier_error_count(trigger, count);
	default:
		abort();
	}
}
