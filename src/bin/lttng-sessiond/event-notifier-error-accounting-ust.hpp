/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UST_HPP
#define LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UST_HPP

#include "event-notifier-error-accounting.hpp"

#include <lttng/trigger/trigger.h>

#include <stdint.h>

/*
 * UST-specific portion of the event notifier error accounting
 * subsystem. The domain-agnostic dispatcher in
 * event-notifier-error-accounting.cpp calls into this interface for
 * the UST-domain branches; the implementation lives in
 * event-notifier-error-accounting-ust.cpp and is only built when the
 * session daemon is compiled with UST support.
 *
 * Inline stubs handle the --without-lttng-ust configuration, matching
 * the ust-sigbus.hpp shape: the daemon cannot serve UST applications,
 * so these entry points are never reached at run time.
 */
namespace lttng {
namespace sessiond {
namespace ust {
namespace event_notifier_error_accounting {

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Initialize the UID-keyed per-user UST counter table. Returns
 * _STATUS_OK on success, _STATUS_NOMEM on allocation failure.
 */
enum event_notifier_error_accounting_status init();

/*
 * Tear down everything that init() set up.
 */
void fini();

/*
 * Record that a UST-domain event notifier has been registered. On the
 * first event notifier, marks every known UID entry as having an
 * event-notifier present so the entries are retained even if all
 * applications of a UID disappear.
 */
void on_event_notifier_registered();

/*
 * Record that a UST-domain event notifier has been unregistered. On
 * the last event notifier, clears the event-notifier-present flag on
 * every UID entry and drops those that no application references.
 */
void on_event_notifier_unregistered();

/*
 * Sum the error counter values across every UID entry for the given
 * trigger. Stores the aggregated value in *count on success.
 */
enum event_notifier_error_accounting_status get_trigger_count(const struct lttng_trigger *trigger,
							      uint64_t *count);

/*
 * Clear the error counter values for the given trigger across every
 * UID entry.
 */
enum event_notifier_error_accounting_status clear_trigger(const struct lttng_trigger *trigger);

#else /* HAVE_LIBLTTNG_UST_CTL */

inline enum event_notifier_error_accounting_status init()
{
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

inline void fini()
{
}

inline void on_event_notifier_registered()
{
}

inline void on_event_notifier_unregistered()
{
}

inline enum event_notifier_error_accounting_status
get_trigger_count(const struct lttng_trigger *trigger __attribute__((unused)), uint64_t *count)
{
	*count = 0;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

inline enum event_notifier_error_accounting_status clear_trigger(const struct lttng_trigger *trigger
								 __attribute__((unused)))
{
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

} /* namespace event_notifier_error_accounting */
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UST_HPP */
