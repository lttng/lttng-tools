/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_TRACE_CLASS_UID_H
#define LTTNG_UST_TRACE_CLASS_UID_H

#include "trace-class.hpp"
#include "ust-trace-class.hpp"

#include <lttng/lttng.h>

#include <cstdint>
#include <unistd.h>

namespace lttng {
namespace sessiond {
namespace ust {

class trace_class_per_uid : public trace_class {
public:
	trace_class_per_uid(enum lttng_trace_format trace_format,
			    const struct lttng::sessiond::trace::abi& trace_abi,
			    uint32_t major,
			    uint32_t minor,
			    const char *root_shm_path,
			    const char *shm_path,
			    uid_t euid,
			    gid_t egid,
			    uint64_t tracing_id,
			    uid_t tracing_uid);

	lttng_buffer_type buffering_scheme() const noexcept final;
	void accept(lttng::sessiond::trace::trace_class_environment_visitor& environment_visitor)
		const final;

private:
	const uid_t _tracing_uid;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_UST_TRACE_CLASS_UID_H */
