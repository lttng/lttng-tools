/*
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "ust-app.hpp"
#include "ust-registry.hpp"
#include "ust-trace-class-pid.hpp"
#include "ust-trace-class-uid.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/hashtable/utils.hpp>
#include <common/make-unique-wrapper.hpp>

#include <lttng/lttng.h>
#include <lttng/ust-ctl.h>

#include <inttypes.h>
#include <string>
#include <type_traits>
#include <unordered_map>

namespace ls = lttng::sessiond;
namespace lst = lttng::sessiond::trace;
namespace lsu = lttng::sessiond::ust;

namespace {
template <class MappingIntegerType>
typename lst::typed_enumeration_type<MappingIntegerType>::mappings
mappings_from_ust_ctl_entries(const lttng_ust_ctl_enum_entry *in_entries, size_t in_entry_count)
{
	using ranges_t =
		typename lst::typed_enumeration_type<MappingIntegerType>::mapping::ranges_t;
	using range_t = typename ranges_t::value_type;
	using tmp_mappings_t = std::unordered_map<std::string, ranges_t>;

	tmp_mappings_t tmp_mappings;

	MappingIntegerType next_range_begin = 0;
	for (size_t entry_idx = 0; entry_idx < in_entry_count; entry_idx++) {
		const auto& entry = in_entries[entry_idx];
		MappingIntegerType range_begin, range_end;

		if (entry.u.extra.options & LTTNG_UST_CTL_UST_ENUM_ENTRY_OPTION_IS_AUTO) {
			range_begin = range_end = next_range_begin;
		} else {
			range_begin = (MappingIntegerType) entry.start.value;
			range_end = (MappingIntegerType) entry.end.value;
		}

		next_range_begin = range_end + 1;

		auto it = tmp_mappings.find(entry.string);

		if (it == tmp_mappings.end()) {
			it = tmp_mappings.emplace(entry.string, ranges_t{}).first;
		}

		it->second.insert(range_t{ range_begin, range_end });
	}

	typename lst::typed_enumeration_type<MappingIntegerType>::mappings mappings;

	for (auto& tmpNameMappingPair : tmp_mappings) {
		mappings.emplace(tmpNameMappingPair.first,
				 typename lst::typed_enumeration_type<MappingIntegerType>::mapping{
					 tmpNameMappingPair.second });
	}

	return mappings;
}
} /* namespace */

template <class MappingIntegerType>
lsu::registry_typed_enum<MappingIntegerType>::registry_typed_enum(
	const char *in_name, const lttng_ust_ctl_enum_entry *entries, size_t entry_count) :
	registry_enum(in_name,
		      std::is_signed<MappingIntegerType>::value ?
			      lst::integer_type::signedness::SIGNED :
			      lst::integer_type::signedness::UNSIGNED),
	_mappings{
		std::make_shared<typename lst::typed_enumeration_type<MappingIntegerType>::mappings>(
			mappings_from_ust_ctl_entries<MappingIntegerType>(entries, entry_count))
	}
{
}

template <class MappingIntegerType>
bool lsu::registry_typed_enum<MappingIntegerType>::_is_equal(
	const registry_enum& base_other) const noexcept
{
	const auto& other = static_cast<const registry_typed_enum&>(base_other);

	/* Don't compare IDs as some comparisons are performed before an id is assigned. */
	return this->name == other.name && *this->_mappings == *other._mappings;
}

/*
 * Explicit instantiations for the two mapping integer types that are
 * actually used. The matching `extern template` declarations in
 * ust-registry.hpp prevent other translation units from attempting their
 * own instantiation.
 */
template class lsu::registry_typed_enum<int64_t>;
template class lsu::registry_typed_enum<uint64_t>;

/*
 * Destroy event function call of the call RCU.
 */
static void ust_event_class_destroy_rcu(struct rcu_head *head)
{
	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	lttng::sessiond::ust::event_class *event =
		lttng::utils::container_of(head, &lttng::sessiond::ust::event_class::_head);
	DIAGNOSTIC_POP

	lttng::sessiond::ust::event_class_destroy(event);
}

/*
 * For a given event in a trace class, delete the entry and destroy the event.
 * This MUST be called within a RCU read side lock section.
 */
void ust_stream_class_destroy_event(lsu::stream_class *chan,
				    lttng::sessiond::ust::event_class *event)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(chan);
	LTTNG_ASSERT(event);
	ASSERT_RCU_READ_LOCKED();

	/* Delete the node first. */
	iter.iter.node = &event->_node;
	ret = lttng_ht_del(chan->_events, &iter);
	LTTNG_ASSERT(!ret);

	call_rcu(&event->_head, ust_event_class_destroy_rcu);

	return;
}

lsu::trace_class *ust_trace_class_per_uid_create(enum lttng_trace_format trace_format,
						 const lttng::sessiond::trace::abi& abi,
						 uint32_t major,
						 uint32_t minor,
						 const char *root_shm_path,
						 const char *shm_path,
						 uid_t euid,
						 gid_t egid,
						 uint64_t tracing_id,
						 uid_t tracing_uid,
						 std::string trace_name,
						 std::string hostname,
						 time_t creation_time)
{
	try {
		return new lsu::trace_class_per_uid(trace_format,
						    abi,
						    major,
						    minor,
						    root_shm_path,
						    shm_path,
						    euid,
						    egid,
						    tracing_id,
						    tracing_uid,
						    std::move(trace_name),
						    std::move(hostname),
						    creation_time);
	} catch (const std::exception& ex) {
		ERR("Failed to create per-UID trace class: %s", ex.what());
		return nullptr;
	}
}

lsu::trace_class *ust_trace_class_per_pid_create(lsu::app *app,
						 enum lttng_trace_format trace_format,
						 const lttng::sessiond::trace::abi& abi,
						 uint32_t major,
						 uint32_t minor,
						 const char *root_shm_path,
						 const char *shm_path,
						 uid_t euid,
						 gid_t egid,
						 uint64_t tracing_id,
						 std::string trace_name,
						 std::string hostname,
						 time_t creation_time)
{
	try {
		return new lsu::trace_class_per_pid(*app,
						    trace_format,
						    abi,
						    major,
						    minor,
						    root_shm_path,
						    shm_path,
						    euid,
						    egid,
						    tracing_id,
						    std::move(trace_name),
						    std::move(hostname),
						    creation_time);
	} catch (const std::exception& ex) {
		ERR("Failed to create per-PID trace class: %s", ex.what());
		return nullptr;
	}
}

/*
 * Destroy a trace class. This does NOT free the given pointer since it
 * might get passed as a reference. The trace class lock should NOT be acquired.
 */
void ust_trace_class_destroy(lsu::trace_class *reg)
{
	delete reg;
}

lsu::registry_enum::registry_enum(std::string in_name,
				  enum lst::integer_type::signedness in_signedness) :
	name{ std::move(in_name) }, signedness{ in_signedness }
{
	cds_lfht_node_init(&this->node.node);
	this->rcu_head = {};
}

bool lsu::operator==(const lsu::registry_enum& lhs, const lsu::registry_enum& rhs) noexcept
{
	if (lhs.signedness != rhs.signedness) {
		return false;
	}

	return lhs._is_equal(rhs);
}
