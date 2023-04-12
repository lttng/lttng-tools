/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_FIELD_CONVERT_H
#define LTTNG_UST_FIELD_CONVERT_H

#include "field.hpp"
#include "ust-registry-session.hpp"
#include "ust-registry.hpp"

#include <cstddef>
#include <type_traits>
#include <vector>

namespace lttng {
namespace sessiond {
namespace ust {

enum class ctl_field_quirks : unsigned int {
	NONE = 0,
	/*
	 * LTTng-UST with ABI major version <= 9 express variants with a tag
	 * enumeration that doesn't match the fields of the variant. The
	 * tag's mapping names are systematically prefixed with an underscore.
	 */
	UNDERSCORE_PREFIXED_VARIANT_TAG_MAPPINGS = 1 << 0,
};

inline ctl_field_quirks operator&(ctl_field_quirks lhs, ctl_field_quirks rhs)
{
	using enum_type = std::underlying_type<ctl_field_quirks>::type;
	return ctl_field_quirks(static_cast<enum_type>(lhs) & static_cast<enum_type>(rhs));
}

inline ctl_field_quirks operator|(ctl_field_quirks lhs, ctl_field_quirks rhs)
{
	using enum_type = std::underlying_type<ctl_field_quirks>::type;
	return ctl_field_quirks(static_cast<enum_type>(lhs) | static_cast<enum_type>(rhs));
}

std::vector<trace::field::cuptr>
create_trace_fields_from_ust_ctl_fields(const lttng::sessiond::ust::registry_session& session,
					const lttng_ust_ctl_field *fields,
					std::size_t field_count,
					trace::field_location::root lookup_root,
					ctl_field_quirks quirks = ctl_field_quirks::NONE);

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_UST_FIELD_CONVERT_H */
