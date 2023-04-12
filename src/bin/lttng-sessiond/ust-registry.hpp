/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_REGISTRY_H
#define LTTNG_UST_REGISTRY_H

#include "event-class.hpp"
#include "field.hpp"
#include "lttng-ust-ctl.hpp"
#include "session.hpp"
#include "stream-class.hpp"
#include "trace-class.hpp"
#include "ust-clock-class.hpp"
#include "ust-registry-channel.hpp"
#include "ust-registry-event.hpp"

#include <common/format.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/locked-reference.hpp>
#include <common/urcu.hpp>
#include <common/uuid.hpp>

#include <lttng/domain.h>

#include <ctime>
#include <memory>
#include <pthread.h>
#include <stdint.h>
#include <string>
#include <type_traits>

#define CTF_SPEC_MAJOR 1
#define CTF_SPEC_MINOR 8

struct ust_app;

namespace lttng {
namespace sessiond {
namespace ust {

class registry_session;

namespace details {

template <class MappingIntegerType>
typename trace::typed_enumeration_type<MappingIntegerType>::mappings
mappings_from_ust_ctl_entries(const lttng_ust_ctl_enum_entry *in_entries, size_t in_entry_count)
{
	typename trace::typed_enumeration_type<MappingIntegerType>::mappings mappings;

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
		mappings.emplace_back(
			entry.string,
			typename trace::typed_enumeration_type<MappingIntegerType>::mapping::range_t{
				range_begin, range_end });
	}

	return mappings;
}
} /* namespace details */

class registry_enum {
public:
	using const_rcu_protected_reference =
		lttng::locked_reference<const registry_enum, lttng::urcu::unique_read_lock>;

	registry_enum(std::string name,
		      enum lttng::sessiond::trace::integer_type::signedness signedness);
	virtual ~registry_enum() = default;
	registry_enum(const registry_enum&) = delete;
	registry_enum(registry_enum&&) = delete;
	registry_enum& operator=(registry_enum&&) = delete;
	registry_enum& operator=(const registry_enum&) = delete;

	std::string name;
	enum lttng::sessiond::trace::integer_type::signedness signedness;
	/* enum id in session */
	uint64_t id = -1ULL;
	/* Enumeration node in session hash table. */
	struct lttng_ht_node_str node;
	/* For delayed reclaim. */
	struct rcu_head rcu_head;

	friend bool operator==(const registry_enum& lhs, const registry_enum& rhs) noexcept;

protected:
	virtual bool _is_equal(const registry_enum& other) const noexcept = 0;
};

bool operator==(const registry_enum& lhs, const registry_enum& rhs) noexcept;

template <class MappingIntegerType>
class registry_typed_enum : public registry_enum {
public:
	registry_typed_enum(const char *in_name,
			    const lttng_ust_ctl_enum_entry *entries,
			    size_t entry_count) :
		registry_enum(in_name,
			      std::is_signed<MappingIntegerType>::value ?
				      lttng::sessiond::trace::integer_type::signedness::SIGNED :
				      lttng::sessiond::trace::integer_type::signedness::UNSIGNED),
		_mappings{ std::make_shared<
			typename trace::typed_enumeration_type<MappingIntegerType>::mappings>(
			details::mappings_from_ust_ctl_entries<MappingIntegerType>(entries,
										   entry_count)) }
	{
	}

	const typename std::shared_ptr<const typename lttng::sessiond::trace::typed_enumeration_type<
		MappingIntegerType>::mappings>
		_mappings;

protected:
	bool _is_equal(const registry_enum& base_other) const noexcept override
	{
		const auto& other = static_cast<decltype(*this)&>(base_other);

		/* Don't compare IDs as some comparisons are performed before an id is assigned. */
		return this->name == other.name && *this->_mappings == *other._mappings;
	}
};

using registry_signed_enum = registry_typed_enum<int64_t>;
using registry_unsigned_enum = registry_typed_enum<uint64_t>;

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Create per-uid registry with default values.
 *
 * Return new instance on success, nullptr on error.
 */
lttng::sessiond::ust::registry_session *
ust_registry_session_per_uid_create(const lttng::sessiond::trace::abi& abi,
				    uint32_t major,
				    uint32_t minor,
				    const char *root_shm_path,
				    const char *shm_path,
				    uid_t euid,
				    gid_t egid,
				    uint64_t tracing_id,
				    uid_t tracing_uid);

/*
 * Create per-pid registry with default values.
 *
 * Return new instance on success, nullptr on error.
 */
lttng::sessiond::ust::registry_session *
ust_registry_session_per_pid_create(struct ust_app *app,
				    const lttng::sessiond::trace::abi& abi,
				    uint32_t major,
				    uint32_t minor,
				    const char *root_shm_path,
				    const char *shm_path,
				    uid_t euid,
				    gid_t egid,
				    uint64_t tracing_id);
void ust_registry_session_destroy(lttng::sessiond::ust::registry_session *session);

void ust_registry_channel_destroy_event(lttng::sessiond::ust::registry_channel *chan,
					lttng::sessiond::ust::registry_event *event);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline lttng::sessiond::ust::registry_session *
ust_registry_session_per_uid_create(uint32_t bits_per_long __attribute__((unused)),
				    uint32_t uint8_t_alignment __attribute__((unused)),
				    uint32_t uint16_t_alignment __attribute__((unused)),
				    uint32_t uint32_t_alignment __attribute__((unused)),
				    uint32_t uint64_t_alignment __attribute__((unused)),
				    uint32_t long_alignment __attribute__((unused)),
				    int byte_order __attribute__((unused)),
				    uint32_t major __attribute__((unused)),
				    uint32_t minor __attribute__((unused)),
				    const char *root_shm_path __attribute__((unused)),
				    const char *shm_path __attribute__((unused)),
				    uid_t euid __attribute__((unused)),
				    gid_t egid __attribute__((unused)),
				    uint64_t tracing_id __attribute__((unused)),
				    uid_t tracing_uid __attribute__((unused)))
{
	return nullptr;
}

static inline lttng::sessiond::ust::registry_session *
ust_registry_session_per_pid_create(struct ust_app *app __attribute__((unused)),
				    uint32_t bits_per_long __attribute__((unused)),
				    uint32_t uint8_t_alignment __attribute__((unused)),
				    uint32_t uint16_t_alignment __attribute__((unused)),
				    uint32_t uint32_t_alignment __attribute__((unused)),
				    uint32_t uint64_t_alignment __attribute__((unused)),
				    uint32_t long_alignment __attribute__((unused)),
				    int byte_order __attribute__((unused)),
				    uint32_t major __attribute__((unused)),
				    uint32_t minor __attribute__((unused)),
				    const char *root_shm_path __attribute__((unused)),
				    const char *shm_path __attribute__((unused)),
				    uid_t euid __attribute__((unused)),
				    gid_t egid __attribute__((unused)),
				    uint64_t tracing_id __attribute__((unused)))
{
	return nullptr;
}

static inline void ust_registry_session_destroy(lttng::sessiond::ust::registry_session *session
						__attribute__((unused)))
{
}

static inline void ust_registry_destroy_event(lttng::sessiond::ust::registry_channel *chan
					      __attribute__((unused)),
					      lttng::sessiond::ust::registry_event *event
					      __attribute__((unused)))
{
}

/* The app object can be NULL for registry shared across applications. */
static inline int ust_metadata_session_statedump(lttng::sessiond::ust::registry_session *session
						 __attribute__((unused)))
{
	return 0;
}

static inline int ust_metadata_channel_statedump(lttng::sessiond::ust::registry_session *session
						 __attribute__((unused)),
						 lttng::sessiond::ust::registry_channel *chan
						 __attribute__((unused)))
{
	return 0;
}

static inline int ust_metadata_event_statedump(lttng::sessiond::ust::registry_session *session
					       __attribute__((unused)),
					       lttng::sessiond::ust::registry_channel *chan
					       __attribute__((unused)),
					       lttng::sessiond::ust::registry_event *event
					       __attribute__((unused)))
{
	return 0;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_UST_REGISTRY_H */
