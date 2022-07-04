/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-app.hpp"
#include "ust-registry-session-pid.hpp"

#include <common/exception.hpp>

namespace lst = lttng::sessiond::trace;
namespace lsu = lttng::sessiond::ust;

lsu::registry_session_per_pid::registry_session_per_pid(const struct ust_app& app,
		const struct lst::abi& in_abi,
		uint32_t major,
		uint32_t minor,
		const char *root_shm_path,
		const char *shm_path,
		uid_t euid,
		gid_t egid,
		uint64_t tracing_id) :
	registry_session{in_abi, major, minor, root_shm_path, shm_path, euid, egid, tracing_id},
	_tracer_patch_level_version{app.version.patchlevel},
	_vpid{app.pid},
	_procname{app.name},
	_app_creation_time{app.registration_time}
{
	lttng::pthread::lock_guard registry_lock(_lock);
	_generate_metadata();
}

lttng_buffer_type lsu::registry_session_per_pid::get_buffering_scheme() const noexcept
{
	return LTTNG_BUFFER_PER_PID;
}

void lsu::registry_session_per_pid::accept(lst::trace_class_environment_visitor& visitor) const
{
	registry_session::accept(visitor);
	visitor.visit(lst::environment_field<int64_t>("tracer_buffering_id", _vpid));
	visitor.visit(lst::environment_field<int64_t>(
			"tracer_patchlevel", _tracer_patch_level_version));
	visitor.visit(lst::environment_field<int64_t>("vpid", _vpid));
	visitor.visit(lst::environment_field<std::string>("procname", _procname));
	visitor.visit(lst::environment_field<std::string>(
			"vpid_datetime", lttng::utils::time_to_iso8601_str(_app_creation_time)));
}
