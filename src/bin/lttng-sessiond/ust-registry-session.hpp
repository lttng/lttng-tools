/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_REGISTRY_SESSION_H
#define LTTNG_UST_REGISTRY_SESSION_H

#include "clock-class.hpp"
#include "session.hpp"
#include "trace-class.hpp"
#include "ust-clock-class.hpp"
#include "ust-registry-channel.hpp"

#include <common/make-unique-wrapper.hpp>

#include <cstdint>
#include <ctime>
#include <lttng/lttng.h>
#include <string>
#include <unistd.h>

namespace lttng {
namespace sessiond {
namespace ust {

class registry_session;

namespace details {
void locked_registry_session_release(registry_session *session);
} /* namespace details */

class registry_session : public lttng::sessiond::trace::trace_class {
public:
	using locked_ptr = std::unique_ptr<registry_session,
			lttng::details::create_unique_class<registry_session,
					details::locked_registry_session_release>::
					deleter>;

	virtual lttng_buffer_type get_buffering_scheme() const noexcept = 0;
	locked_ptr lock();

	void add_channel(uint64_t channel_key);
	lttng::sessiond::ust::registry_channel& get_channel(uint64_t channel_key) const;
	void remove_channel(uint64_t channel_key, bool notify);

	void regenerate_metadata();
	virtual ~registry_session();

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
	registry_session(const struct lttng::sessiond::trace::abi& abi,
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

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_UST_REGISTRY_SESSION_H */
