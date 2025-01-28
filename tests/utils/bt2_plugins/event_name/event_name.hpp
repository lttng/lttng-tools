/*
 * SPDX-FileCopyrightText: 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TEST_UTILS_BT2_PLUGIN_EVENT_NAME_HPP
#define LTTNG_TEST_UTILS_BT2_PLUGIN_EVENT_NAME_HPP

#include <babeltrace2/babeltrace.h>

bt_component_class_initialize_method_status
event_name_initialize(bt_self_component_filter *self_comp,
		      bt_self_component_filter_configuration *config,
		      const bt_value *params,
		      void *init_data);

void event_name_finalize(bt_self_component_filter *self_comp);

bt_message_iterator_class_initialize_method_status
event_name_message_iterator_initialize(bt_self_message_iterator *self_message_iterator,
				       bt_self_message_iterator_configuration *config,
				       bt_self_component_port_output *self_port);

void event_name_message_iterator_finalize(bt_self_message_iterator *self_message_iterator);

bt_message_iterator_class_next_method_status
event_name_message_iterator_next(bt_self_message_iterator *self_message_iterator,
				 bt_message_array_const messages,
				 uint64_t capacity,
				 uint64_t *count);

#endif /* LTTNG_TEST_UTILS_BT2_PLUGIN_EVENT_NAME_HPP */
