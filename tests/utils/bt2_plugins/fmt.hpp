/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TESTS_UTILS_BT2_PLUGINS_FMT_H
#define LTTNG_TESTS_UTILS_BT2_PLUGINS_FMT_H

#include <common/format.hpp>

#include <babeltrace2/babeltrace.h>

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<bt_field_class_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const bt_field_class_type field_class_type,
						    FormatContextType& ctx) const
	{
		const char *name;

		switch (field_class_type) {
		case BT_FIELD_CLASS_TYPE_BOOL:
			name = "BOOL";
			break;
		case BT_FIELD_CLASS_TYPE_BIT_ARRAY:
			name = "BIT_ARRAY";
			break;
		case BT_FIELD_CLASS_TYPE_INTEGER:
			name = "INTEGER";
			break;
		case BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER:
			name = "UNSIGNED_INTEGER";
			break;
		case BT_FIELD_CLASS_TYPE_SIGNED_INTEGER:
			name = "SIGNED_INTEGER";
			break;
		case BT_FIELD_CLASS_TYPE_ENUMERATION:
			name = "ENUMERATION";
			break;
		case BT_FIELD_CLASS_TYPE_UNSIGNED_ENUMERATION:
			name = "UNSIGNED_ENUMERATION";
			break;
		case BT_FIELD_CLASS_TYPE_SIGNED_ENUMERATION:
			name = "SIGNED_ENUMERATION";
			break;
		case BT_FIELD_CLASS_TYPE_REAL:
			name = "REAL";
			break;
		case BT_FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL:
			name = "SINGLE_PRECISION_REAL";
			break;
		case BT_FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL:
			name = "DOUBLE_PRECISION_REAL";
			break;
		case BT_FIELD_CLASS_TYPE_STRING:
			name = "STRING";
			break;
		case BT_FIELD_CLASS_TYPE_STRUCTURE:
			name = "STRUCTURE";
			break;
		case BT_FIELD_CLASS_TYPE_ARRAY:
			name = "ARRAY";
			break;
		case BT_FIELD_CLASS_TYPE_STATIC_ARRAY:
			name = "STATIC_ARRAY";
			break;
		case BT_FIELD_CLASS_TYPE_DYNAMIC_ARRAY:
			name = "DYNAMIC_ARRAY";
			break;
		case BT_FIELD_CLASS_TYPE_DYNAMIC_ARRAY_WITHOUT_LENGTH_FIELD:
			name = "DYNAMIC_ARRAY_WITHOUT_LENGTH_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_DYNAMIC_ARRAY_WITH_LENGTH_FIELD:
			name = "DYNAMIC_ARRAY_WITH_LENGTH_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_OPTION:
			name = "OPTION";
			break;
		case BT_FIELD_CLASS_TYPE_OPTION_WITHOUT_SELECTOR_FIELD:
			name = "OPTION_WITHOUT_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_OPTION_WITH_SELECTOR_FIELD:
			name = "OPTION_WITH_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_OPTION_WITH_BOOL_SELECTOR_FIELD:
			name = "OPTION_WITH_BOOL_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_OPTION_WITH_INTEGER_SELECTOR_FIELD:
			name = "OPTION_WITH_INTEGER_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_OPTION_WITH_UNSIGNED_INTEGER_SELECTOR_FIELD:
			name = "OPTION_WITH_UNSIGNED_INTEGER_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_OPTION_WITH_SIGNED_INTEGER_SELECTOR_FIELD:
			name = "OPTION_WITH_SIGNED_INTEGER_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_VARIANT:
			name = "VARIANT";
			break;
		case BT_FIELD_CLASS_TYPE_VARIANT_WITHOUT_SELECTOR_FIELD:
			name = "VARIANT_WITHOUT_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_VARIANT_WITH_SELECTOR_FIELD:
			name = "VARIANT_WITH_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_VARIANT_WITH_INTEGER_SELECTOR_FIELD:
			name = "VARIANT_WITH_INTEGER_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_VARIANT_WITH_UNSIGNED_INTEGER_SELECTOR_FIELD:
			name = "VARIANT_WITH_UNSIGNED_INTEGER_SELECTOR_FIELD";
			break;
		case BT_FIELD_CLASS_TYPE_VARIANT_WITH_SIGNED_INTEGER_SELECTOR_FIELD:
			name = "VARIANT_WITH_SIGNED_INTEGER_SELECTOR_FIELD";
			break;
		default:
			abort();
		}

		return format_to(ctx.out(), name);
	}
};
} /* namespace fmt */

#endif /* LTTNG_TESTS_UTILS_BT2_PLUGINS_FMT_H */
