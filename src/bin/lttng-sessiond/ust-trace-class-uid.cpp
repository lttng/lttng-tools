/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-trace-class-uid.hpp"

namespace lst = lttng::sessiond::trace;
namespace lsu = lttng::sessiond::ust;

lsu::trace_class_per_uid::trace_class_per_uid(enum lttng_trace_format trace_format,
					      const struct lst::abi& in_abi,
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
					      time_t creation_time) :
	trace_class{ trace_format,
		     in_abi,
		     major,
		     minor,
		     root_shm_path,
		     shm_path,
		     euid,
		     egid,
		     tracing_id,
		     std::move(trace_name),
		     std::move(hostname),
		     creation_time },
	_tracing_uid{ tracing_uid }
{
	const lttng::pthread::lock_guard registry_lock(_lock);
	_generate_metadata();
}

lttng_buffer_type lsu::trace_class_per_uid::buffering_scheme() const noexcept
{
	return LTTNG_BUFFER_PER_UID;
}

void lsu::trace_class_per_uid::accept(lst::trace_class_environment_visitor& visitor) const
{
	trace_class::accept(visitor);
	visitor.visit(lst::environment_field<int64_t>("tracer_buffering_id", _tracing_uid));
}
