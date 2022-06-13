/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_FIELD_CONVERT_H
#define LTTNG_UST_FIELD_CONVERT_H

#include "field.hpp"
#include "ust-registry.hpp"

#include <cstddef>
#include <vector>

namespace lttng {
namespace sessiond {
namespace ust {

std::vector<trace::field::cuptr> create_trace_fields_from_ust_ctl_fields(
		const ust_registry_session& session,
		const lttng_ust_ctl_field *fields,
		std::size_t field_count);

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_UST_FIELD_CONVERT_H */
