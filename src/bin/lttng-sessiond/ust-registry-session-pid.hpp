/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_REGISTRY_SESSION_PID_H
#define LTTNG_UST_REGISTRY_SESSION_PID_H

#include "trace-class.hpp"
#include "ust-registry-session.hpp"

#include <lttng/lttng.h>

#include <cstdint>
#include <ctime>
#include <string>
#include <unistd.h>

namespace lttng {
namespace sessiond {
namespace ust {

class registry_session_per_pid : public registry_session {
public:
	registry_session_per_pid(const struct ust_app& app,
				 const struct lttng::sessiond::trace::abi& trace_abi,
				 uint32_t major,
				 uint32_t minor,
				 const char *root_shm_path,
				 const char *shm_path,
				 uid_t euid,
				 gid_t egid,
				 uint64_t tracing_id);

	virtual lttng_buffer_type buffering_scheme() const noexcept override final;
	virtual void accept(lttng::sessiond::trace::trace_class_environment_visitor&
				    environment_visitor) const override final;

private:
	const unsigned int _tracer_patch_level_version;
	const pid_t _vpid;
	const std::string _procname;
	const std::time_t _app_creation_time;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_UST_REGISTRY_SESSION_PID_H */
