/*
 * SPDX-FileCopyrightText: 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "event_name/event_name.hpp"
#include "field_stats/field_stats.hpp"

#include <babeltrace2/babeltrace.h>

BT_PLUGIN_MODULE();

BT_PLUGIN(lttngtest);
BT_PLUGIN_DESCRIPTION("Filter and sink used in lttng-tools test suite");
BT_PLUGIN_AUTHOR("Kienan Stewart");
BT_PLUGIN_LICENSE("LGPL-2.1-only");

/* flt.lttngtest.event_name */
/* Filter class to pass events matching given names */
BT_PLUGIN_FILTER_COMPONENT_CLASS(event_name, event_name_message_iterator_next);
BT_PLUGIN_FILTER_COMPONENT_CLASS_DESCRIPTION(event_name, "Filter events by tracepoint name(s)");
BT_PLUGIN_FILTER_COMPONENT_CLASS_INITIALIZE_METHOD(event_name, event_name_initialize);
BT_PLUGIN_FILTER_COMPONENT_CLASS_FINALIZE_METHOD(event_name, event_name_finalize);
BT_PLUGIN_FILTER_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD(
	event_name, event_name_message_iterator_initialize);
BT_PLUGIN_FILTER_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_FINALIZE_METHOD(
	event_name, event_name_message_iterator_finalize);

/* sink.lttngtest.field_stats */
/* Sink class to produce certain statistics for seen fields */
BT_PLUGIN_SINK_COMPONENT_CLASS(field_stats, field_stats_consume);
BT_PLUGIN_SINK_COMPONENT_CLASS_DESCRIPTION(field_stats,
					   "Track minimum and maxiumum values of seen fields");
BT_PLUGIN_SINK_COMPONENT_CLASS_INITIALIZE_METHOD(field_stats, field_stats_initialize);
BT_PLUGIN_SINK_COMPONENT_CLASS_FINALIZE_METHOD(field_stats, field_stats_finalize);
BT_PLUGIN_SINK_COMPONENT_CLASS_GRAPH_IS_CONFIGURED_METHOD(field_stats,
							  field_stats_graph_is_configured);
