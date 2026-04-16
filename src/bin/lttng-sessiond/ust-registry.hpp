/*
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_REGISTRY_H
#define LTTNG_UST_REGISTRY_H

#include "event-class.hpp"
#include "field.hpp"
#include "stream-class.hpp"
#include "trace-class.hpp"
#include "ust-clock-class.hpp"
#include "ust-event-class.hpp"
#include "ust-field-quirks.hpp"
#include "ust-stream-class.hpp"

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
#include <unordered_set>
#include <utility>

#define CTF_SPEC_MAJOR 1
#define CTF_SPEC_MINOR 8

/*
 * Forward declaration of the lttng-ust-ctl enumeration entry type.  Keeping
 * this as a forward declaration (rather than including <lttng/ust-ctl.h>)
 * allows this header to be used from translation units compiled without
 * lttng-ust-ctl; the full definition is only required by the out-of-line
 * implementation of registry_typed_enum, which lives in ust-registry.cpp.
 */
struct lttng_ust_ctl_enum_entry;

namespace lttng {
namespace sessiond {
namespace ust {
struct app;

class trace_class;

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
			    size_t entry_count);

	const std::shared_ptr<const typename lttng::sessiond::trace::typed_enumeration_type<
		MappingIntegerType>::mappings>
		_mappings;

protected:
	bool _is_equal(const registry_enum& base_other) const noexcept override;
};

/*
 * The member functions of registry_typed_enum are defined out-of-line in
 * ust-registry.cpp because the constructor consumes lttng_ust_ctl_enum_entry
 * objects, whose full definition is supplied by <lttng/ust-ctl.h>. Keeping
 * the definitions in a translation unit that is only compiled when
 * HAVE_LIBLTTNG_UST_CTL is set lets this always-built header stay free of
 * any lttng-ust-ctl dependency.
 *
 * Only the two instantiations below are ever used, so ust-registry.cpp
 * supplies an explicit instantiation definition for each. The matching
 * extern declarations here prevent other translation units from performing
 * their own (necessarily incomplete) implicit instantiation when they only
 * see this header.
 */
extern template class registry_typed_enum<int64_t>;
extern template class registry_typed_enum<uint64_t>;

using registry_signed_enum = registry_typed_enum<int64_t>;
using registry_unsigned_enum = registry_typed_enum<uint64_t>;

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Create per-uid registry with default values.
 *
 * Return new instance on success, nullptr on error.
 */
lttng::sessiond::ust::trace_class *
ust_trace_class_per_uid_create(enum lttng_trace_format trace_format,
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
			       time_t creation_time);

/*
 * Create per-pid registry with default values.
 *
 * Return new instance on success, nullptr on error.
 */
lttng::sessiond::ust::trace_class *
ust_trace_class_per_pid_create(lttng::sessiond::ust::app *app,
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
			       time_t creation_time);
void ust_trace_class_destroy(lttng::sessiond::ust::trace_class *session);

void ust_stream_class_destroy_event(lttng::sessiond::ust::stream_class *chan,
				    lttng::sessiond::ust::event_class *event);

#endif /* LTTNG_UST_REGISTRY_H */
