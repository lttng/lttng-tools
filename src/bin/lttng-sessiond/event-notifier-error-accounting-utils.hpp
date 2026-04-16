/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP
#define LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP

#include "event-notifier-error-accounting.hpp"

#include <common/hashtable/hashtable.hpp>
#include <common/index-allocator.hpp>

#include <lttng/trigger/trigger.h>

#include <stdint.h>
#include <sys/types.h>

/*
 * Per-domain (UST or kernel) event notifier error counter state shared
 * between the domain-agnostic dispatcher (event-notifier-error-accounting.cpp)
 * and the UST-specific implementation (event-notifier-error-accounting-ust.cpp).
 */
struct error_accounting_state {
	struct lttng_index_allocator *index_allocator;
	/* Hashtable mapping event notifier token to index_ht_entry. */
	struct lttng_ht *indices_ht;
	uint64_t number_indices;
};

extern struct error_accounting_state ust_state;

/*
 * Return the error counter index associated to this event notifier
 * tracer token. Returns _STATUS_OK if found and _STATUS_NOT_FOUND
 * otherwise.
 */
enum event_notifier_error_accounting_status get_error_counter_index_for_token(
	struct error_accounting_state *state, uint64_t tracer_token, uint64_t *error_counter_index);

void get_trigger_info_for_log(const struct lttng_trigger *trigger,
			      const char **trigger_name,
			      uid_t *trigger_owner_uid);

const char *error_accounting_status_str(enum event_notifier_error_accounting_status status);

#endif /* LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP */
