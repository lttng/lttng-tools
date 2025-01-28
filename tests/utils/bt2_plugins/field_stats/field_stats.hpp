/*
 * SPDX-FileCopyrightText: 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TEST_UTILS_BT2_PLUGIN_FIELD_STATS_HPP
#define LTTNG_TEST_UTILS_BT2_PLUGIN_FIELD_STATS_HPP

#include <babeltrace2/babeltrace.h>

bt_component_class_initialize_method_status
field_stats_initialize(bt_self_component_sink *self_component_sink,
		       bt_self_component_sink_configuration *config,
		       const bt_value *params,
		       void *initialize_method_data);

void field_stats_finalize(bt_self_component_sink *self_component_sink);

bt_component_class_sink_graph_is_configured_method_status
field_stats_graph_is_configured(bt_self_component_sink *self_component_sink);

bt_component_class_sink_consume_method_status
field_stats_consume(bt_self_component_sink *self_component_sink);

#endif /* LTTNG_TEST_UTILS_BT2_PLUGIN_FIELD_STATS_HPP */
