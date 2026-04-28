/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_KERNEL_HPP
#define LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_KERNEL_HPP

#include "event-notifier-error-accounting.hpp"

#include <lttng/trigger/trigger.h>

#include <stdint.h>

/*
 * Kernel-domain backend for the event notifier error accounting
 * subsystem. Mirrors the namespace-level surface of the UST backend in
 * event-notifier-error-accounting-ust.hpp; the dispatcher in
 * event-notifier-error-accounting.cpp routes per-domain calls to the
 * matching backend.
 */
namespace lttng {
namespace sessiond {
namespace modules {
namespace event_notifier_error_accounting {

/*
 * Initialize kernel-side accounting state, sized to `index_count` error
 * counter slots.
 */
enum event_notifier_error_accounting_status init(uint64_t index_count);

/*
 * Tear down everything that init() set up.
 */
void fini();

/*
 * Create the kernel event notifier group's error counter object,
 * attached to the provided fd.
 */
enum event_notifier_error_accounting_status register_kernel(int kernel_event_notifier_group_fd);

/*
 * Allocate and register an error counter index for the given trigger,
 * returning it in *error_counter_index.
 */
enum event_notifier_error_accounting_status
register_event_notifier(const struct lttng_trigger *trigger, uint64_t *error_counter_index);

/*
 * Clear the trigger's counter slot and release its index.
 */
void unregister_event_notifier(const struct lttng_trigger *trigger);

/*
 * Read the trigger's current error counter value into *count.
 */
enum event_notifier_error_accounting_status get_trigger_count(const struct lttng_trigger *trigger,
							      uint64_t *count);

} /* namespace event_notifier_error_accounting */
} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_KERNEL_HPP */
