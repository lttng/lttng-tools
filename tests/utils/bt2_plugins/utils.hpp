/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TEST_UTILS_BT2_PLUGIN_UTILS_HPP
#define LTTNG_TEST_UTILS_BT2_PLUGIN_UTILS_HPP

#include <common/make-unique-wrapper.hpp>

#include <babeltrace2/babeltrace.h>

namespace lttng {
namespace bt2 {
namespace internal {
static inline void bt_value_put_ref(bt_value *value)
{
	bt_value_put_ref(static_cast<const bt_value *>(value));
}
} /* namespace internal */

using value_ref = std::unique_ptr<
	bt_value,
	lttng::memory::create_deleter_class<bt_value, internal::bt_value_put_ref>::deleter>;

using event_class_const_ref = std::unique_ptr<
	const bt_event_class,
	lttng::memory::create_deleter_class<const bt_event_class, bt_event_class_put_ref>::deleter>;

static inline value_ref make_value_ref(bt_value *instance)
{
	const memory::create_deleter_class<bt_value, internal::bt_value_put_ref> unique_deleter;
	return unique_deleter(instance);
}

using message_const_ref = std::unique_ptr<
	const bt_message,
	lttng::memory::create_deleter_class<const bt_message, bt_message_put_ref>::deleter>;

using message_iterator_ref =
	std::unique_ptr<bt_message_iterator,
			lttng::memory::create_deleter_class<const bt_message_iterator,
							    bt_message_iterator_put_ref>::deleter>;
} /* namespace bt2 */
} /* namespace lttng */

#endif /* LTTNG_TEST_UTILS_BT2_PLUGIN_UTILS_HPP */
