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

#include <cstdint>
#include <sys/types.h>

/*
 * UST-domain backend for the event notifier error accounting
 * subsystem. The domain-agnostic dispatcher in
 * event-notifier-error-accounting.cpp forwards UST-domain operations
 * to this interface; the implementation lives in
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
 * Initialize the UID-keyed per-user UST counter table with a counter
 * pool of `index_count` elements.
 */
enum event_notifier_error_accounting_status init(std::uint64_t index_count);

/*
 * Tear down everything that init() set up.
 */
void fini();

/*
 * Allocate (or look up) an error counter index for the trigger and
 * record the new event notifier registration. Stores the index in
 * *error_counter_index on success.
 */
enum event_notifier_error_accounting_status
register_event_notifier(const struct lttng_trigger *trigger, std::uint64_t *error_counter_index);

/*
 * Clear the trigger's counter across every UID entry, drop the
 * registration, and release the trigger's index.
 */
void unregister_event_notifier(const struct lttng_trigger *trigger);

/*
 * Sum the error counter values across every UID entry for the given
 * trigger. Stores the aggregated value in *count on success.
 */
enum event_notifier_error_accounting_status get_trigger_count(const struct lttng_trigger *trigger,
							      std::uint64_t *count);

namespace details {

/*
 * Defined in event-notifier-error-accounting-ust.cpp; held by reference
 * from `uid_entry_reference` so callers do not need the full type.
 */
struct ust_uid_map_group_entry;

/*
 * RAII handle for an app's reference to the UID-keyed entry that owns
 * per-user error counters.
 *
 * Constructing finds (or creates) the entry and bumps its attached_app_count
 * (effectively a ref count) under the accounting lock.
 *
 * The destructor decrements the count and drops the entry if no app and no
 * event notifier reference it.
 *
 * Move/copy are disabled: take the reference by emplacing into
 * `app->event_notifier_group.accounting_reference`, release it by
 * resetting that optional.
 */
class uid_entry_reference {
public:
	explicit uid_entry_reference(uid_t uid);

	uid_entry_reference(const uid_entry_reference&) = delete;
	uid_entry_reference& operator=(const uid_entry_reference&) = delete;
	uid_entry_reference(uid_entry_reference&&) = delete;
	uid_entry_reference& operator=(uid_entry_reference&&) = delete;

	~uid_entry_reference();

	ust_uid_map_group_entry& entry() const noexcept;

private:
	const uid_t _uid;
	ust_uid_map_group_entry& _entry;
};

} /* namespace details */

#else /* HAVE_LIBLTTNG_UST_CTL */

inline enum event_notifier_error_accounting_status init(std::uint64_t index_count
							__attribute__((unused)))
{
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

inline void fini()
{
}

inline enum event_notifier_error_accounting_status
register_event_notifier(const struct lttng_trigger *trigger __attribute__((unused)),
			std::uint64_t *error_counter_index __attribute__((unused)))
{
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

inline void unregister_event_notifier(const struct lttng_trigger *trigger __attribute__((unused)))
{
}

inline enum event_notifier_error_accounting_status
get_trigger_count(const struct lttng_trigger *trigger __attribute__((unused)), std::uint64_t *count)
{
	*count = 0;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

} /* namespace event_notifier_error_accounting */
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UST_HPP */
