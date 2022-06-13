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

#define CTF_SPEC_MAJOR	1
#define CTF_SPEC_MINOR	8

struct ust_app;
class ust_registry_session;

namespace lttng {
namespace sessiond {
namespace details {
void locked_ust_registry_session_release(ust_registry_session *session);
} /* namespace details */
} /* namespace sessiond */
} /* namespace lttng */

class ust_registry_session : public lttng::sessiond::trace::trace_class {
public:
	using locked_ptr = std::unique_ptr<ust_registry_session,
			lttng::details::create_unique_class<ust_registry_session,
					lttng::sessiond::details::locked_ust_registry_session_release>::
					deleter>;

	virtual lttng_buffer_type get_buffering_scheme() const noexcept = 0;
	locked_ptr lock();

	void add_channel(uint64_t channel_key);
	lttng::sessiond::ust::registry_channel& get_channel(uint64_t channel_key) const;
	void remove_channel(uint64_t channel_key, bool notify);

	void regenerate_metadata();
	virtual ~ust_registry_session();

	/*
	 * With multiple writers and readers, use this lock to access
	 * the registry. Can nest within the ust app session lock.
	 * Also acts as a registry serialization lock. Used by registry
	 * readers to serialize the registry information sent from the
	 * sessiond to the consumerd.
	 * The consumer socket lock nests within this lock.
	 */
	mutable pthread_mutex_t _lock;
	/* Next channel ID available for a newly registered channel. */
	uint32_t _next_channel_id = 0;
	/* Once this value reaches UINT32_MAX, no more id can be allocated. */
	uint32_t _used_channel_id = 0;
	/* Next enumeration ID available. */
	uint64_t _next_enum_id = 0;

	/* Generated metadata. */
	char *_metadata = nullptr; /* NOT null-terminated ! Use memcpy. */
	size_t _metadata_len = 0, _metadata_alloc_len = 0;
	/* Length of bytes sent to the consumer. */
	size_t _metadata_len_sent = 0;
	/* Current version of the metadata. */
	uint64_t _metadata_version = 0;

	/*
	 * Those fields are only used when a session is created with
	 * the --shm-path option. In this case, the metadata is output
	 * twice: once to the consumer, as ususal, but a second time
	 * also in the shm path directly. This is done so that a copy
	 * of the metadata that is as fresh as possible is available
	 * on the event of a crash.
	 *
	 * root_shm_path contains the shm-path provided by the user, along with
	 * the session's name and timestamp:
	 *   e.g. /tmp/my_shm/my_session-20180612-135822
	 *
	 * shm_path contains the full path of the memory buffers:
	 *   e.g. /tmp/my_shm/my_session-20180612-135822/ust/uid/1000/64-bit
	 *
	 * metadata_path contains the full path to the metadata file that
	 * is kept for the "crash buffer" extraction:
	 *  e.g.
	 * /tmp/my_shm/my_session-20180612-135822/ust/uid/1000/64-bit/metadata
	 *
	 * Note that this is not the trace's final metadata file. It is
	 * only meant to be used to read the contents of the ring buffers
	 * in the event of a crash.
	 *
	 * metadata_fd is a file descriptor that points to the file at
	 * 'metadata_path'.
	 */
	char _root_shm_path[PATH_MAX] = {};
	char _shm_path[PATH_MAX] = {};
	char _metadata_path[PATH_MAX] = {};
	/* File-backed metadata FD */
	int _metadata_fd = -1;

	/*
	 * Hash table containing channels sent by the UST tracer. MUST
	 * be accessed with a RCU read side lock acquired.
	 */
	lttng_ht::uptr _channels;

	/*
	 * Unique key to identify the metadata on the consumer side.
	 */
	uint64_t _metadata_key = 0;
	/*
	 * Indicates if the metadata is closed on the consumer side. This is to
	 * avoid double close of metadata when an application unregisters AND
	 * deletes its sessions.
	 */
	bool _metadata_closed = false;

	/* User and group owning the session. */
	uid_t _uid = -1;
	gid_t _gid = -1;

	/* Enumerations table. */
	lttng_ht::uptr _enums;

	/*
	 * Copy of the tracer version when the first app is registered.
	 * It is used if we need to regenerate the metadata.
	 */
	uint32_t _app_tracer_version_major = 0;
	uint32_t _app_tracer_version_minor = 0;

	/* The id of the parent session */
	ltt_session::id_t _tracing_id = -1ULL;

protected:
	/* Prevent instanciation of this base class. */
	ust_registry_session(const struct lttng::sessiond::trace::abi& abi,
			unsigned int app_tracer_version_major,
			unsigned int app_tracer_version_minor,
			const char *root_shm_path,
			const char *shm_path,
			uid_t euid,
			gid_t egid,
			uint64_t tracing_id);
	virtual void _visit_environment(
			lttng::sessiond::trace::trace_class_visitor& trace_class_visitor)
			const override;
	void _generate_metadata();

private:
	uint32_t _get_next_channel_id();
	void _increase_metadata_size(size_t reservation_length);
	void _append_metadata_fragment(const std::string& fragment);
	void _reset_metadata();

	virtual void _accept_on_clock_classes(
			lttng::sessiond::trace::trace_class_visitor& trace_class_visitor)
			const override final;
	virtual void _accept_on_stream_classes(
			lttng::sessiond::trace::trace_class_visitor& trace_class_visitor)
			const override final;

	lttng::sessiond::ust::clock_class _clock;
	const lttng::sessiond::trace::trace_class_visitor::cuptr _metadata_generating_visitor;
};

class ust_registry_session_per_uid : public ust_registry_session {
public:
	ust_registry_session_per_uid(const struct lttng::sessiond::trace::abi& trace_abi,
			uint32_t major,
			uint32_t minor,
			const char *root_shm_path,
			const char *shm_path,
			uid_t euid,
			gid_t egid,
			uint64_t tracing_id,
			uid_t tracing_uid);

	virtual lttng_buffer_type get_buffering_scheme() const noexcept override final;

private:
	virtual void _visit_environment(
			lttng::sessiond::trace::trace_class_visitor& trace_class_visitor)
			const override final;

	const uid_t _tracing_uid;
};

class ust_registry_session_per_pid : public ust_registry_session {
public:
	ust_registry_session_per_pid(const struct ust_app& app,
			const struct lttng::sessiond::trace::abi&
					trace_abi,
			uint32_t major,
			uint32_t minor,
			const char *root_shm_path,
			const char *shm_path,
			uid_t euid,
			gid_t egid,
			uint64_t tracing_id);

	virtual lttng_buffer_type get_buffering_scheme() const noexcept override final;

private:
	virtual void _visit_environment(
			lttng::sessiond::trace::trace_class_visitor& trace_class_visitor)
			const override final;

	const unsigned int _tracer_patch_level_version;
	const pid_t _vpid;
	const std::string _procname;
	const std::time_t _app_creation_time;
};


namespace lttng {
namespace sessiond {
namespace ust {

class registry_enum {
public:
	using const_rcu_protected_reference = lttng::locked_reference<const registry_enum, lttng::urcu::unique_read_lock>;

	registry_enum(std::string name, enum lttng::sessiond::trace::integer_type::signedness signedness);
	virtual ~registry_enum() = default;

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

namespace details {
template <class MappingIntegerType>
typename trace::typed_enumeration_type<MappingIntegerType>::mapping mapping_from_ust_ctl_entry(
		const lttng_ust_ctl_enum_entry& entry)
{
	if (entry.u.extra.options & LTTNG_UST_CTL_UST_ENUM_ENTRY_OPTION_IS_AUTO) {
		return {entry.string};

	} else {
		return {entry.string,
				{(MappingIntegerType) entry.start.value,
						(MappingIntegerType) entry.end.value}};
	}
}

template <class MappingIntegerType>
typename trace::typed_enumeration_type<MappingIntegerType>::mappings mappings_from_ust_ctl_entries(
		const lttng_ust_ctl_enum_entry *in_entries, size_t in_entry_count)
{
	typename trace::typed_enumeration_type<MappingIntegerType>::mappings mappings;

	for (size_t entry_idx = 0; entry_idx < in_entry_count; entry_idx++) {
		const auto& entry = in_entries[entry_idx];

		mappings.emplace_back(mapping_from_ust_ctl_entry<MappingIntegerType>(entry));
	}

	return mappings;
}
} /* namespace details */

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
		_mappings{std::make_shared<
				typename trace::typed_enumeration_type<MappingIntegerType>::mappings>(
				details::mappings_from_ust_ctl_entries<MappingIntegerType>(
						entries, entry_count))}
	{
	}

	const typename std::shared_ptr<const typename lttng::sessiond::trace::typed_enumeration_type<
			MappingIntegerType>::mappings>
			_mappings;

protected:
	virtual bool _is_equal(const registry_enum& base_other) const noexcept
	{
		const auto &other = static_cast<decltype(*this)&>(base_other);

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
ust_registry_session *ust_registry_session_per_uid_create(
		const lttng::sessiond::trace::abi& abi,
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
ust_registry_session *ust_registry_session_per_pid_create(struct ust_app *app,
		const lttng::sessiond::trace::abi& abi,
		uint32_t major,
		uint32_t minor,
		const char *root_shm_path,
		const char *shm_path,
		uid_t euid,
		gid_t egid,
		uint64_t tracing_id);
void ust_registry_session_destroy(ust_registry_session *session);

void ust_registry_channel_destroy_event(lttng::sessiond::ust::registry_channel *chan,
		lttng::sessiond::ust::registry_event *event);

int ust_registry_create_or_find_enum(ust_registry_session *session,
		int session_objd, char *name,
		struct lttng_ust_ctl_enum_entry *entries, size_t nr_entries,
		uint64_t *enum_id);
lttng::sessiond::ust::registry_enum::const_rcu_protected_reference
ust_registry_lookup_enum_by_id(const ust_registry_session *session,
		const char *name, uint64_t id);
void ust_registry_destroy_enum(ust_registry_session *reg_session,
		lttng::sessiond::ust::registry_enum *reg_enum);
#else /* HAVE_LIBLTTNG_UST_CTL */

static inline
ust_registry_session *ust_registry_session_per_uid_create(
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
		uint64_t tracing_id __attribute__((unused)),
		uid_t tracing_uid __attribute__((unused)))
{
	return nullptr;
}

static inline
ust_registry_session *ust_registry_session_per_pid_create(
		struct ust_app *app __attribute__((unused)),
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

static inline
void ust_registry_session_destroy(
		ust_registry_session *session __attribute__((unused)))
{}

static inline
void ust_registry_destroy_event(
		lttng::sessiond::ust::registry_channel *chan __attribute__((unused)),
		lttng::sessiond::ust::registry_event *event __attribute__((unused)))
{}

/* The app object can be NULL for registry shared across applications. */
static inline
int ust_metadata_session_statedump(
		ust_registry_session *session __attribute__((unused)))
{
	return 0;
}

static inline
int ust_metadata_channel_statedump(
		ust_registry_session *session __attribute__((unused)),
		lttng::sessiond::ust::registry_channel *chan __attribute__((unused)))
{
	return 0;
}

static inline
int ust_metadata_event_statedump(
		ust_registry_session *session __attribute__((unused)),
		lttng::sessiond::ust::registry_channel *chan __attribute__((unused)),
		lttng::sessiond::ust::registry_event *event __attribute__((unused)))
{
	return 0;
}

static inline
int ust_registry_create_or_find_enum(
		ust_registry_session *session __attribute__((unused)),
		int session_objd __attribute__((unused)),
		char *name __attribute__((unused)),
		struct lttng_ust_ctl_enum_entry *entries __attribute__((unused)),
		size_t nr_entries __attribute__((unused)),
		uint64_t *enum_id __attribute__((unused)))
{
	return 0;
}

static inline
struct ust_registry_enum *
	ust_registry_lookup_enum_by_id(
		const ust_registry_session *session __attribute__((unused)),
		const char *name __attribute__((unused)),
		uint64_t id __attribute__((unused)))
{
	return NULL;
}

static inline
void ust_registry_destroy_enum(ust_registry_session *reg_session __attribute__((unused)),
		struct ust_registry_enum *reg_enum __attribute__((unused)))
{}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_UST_REGISTRY_H */
