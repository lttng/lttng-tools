/**
 * Copyright (C) 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "../fmt.hpp"
#include "field_stats.hpp"

#include <assert.h>
#include <babeltrace2/babeltrace.h>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>

struct field_stats {
	bt_message_iterator *iterator;
	bt_value *stats_value;
	const bt_event_class *event_class;
};

bt_component_class_initialize_method_status
field_stats_initialize(bt_self_component_sink *self_component_sink,
		       bt_self_component_sink_configuration *,
		       const bt_value *,
		       void *)
{
	bt_component_class_initialize_method_status status;
	struct field_stats *field_stats = nullptr;

	if (bt_self_component_sink_add_input_port(self_component_sink, "in", nullptr, nullptr) !=
	    BT_SELF_COMPONENT_ADD_PORT_STATUS_OK) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"Failed to add input port");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
		goto error;
	}

	field_stats = (struct field_stats *) malloc(sizeof(*field_stats));
	if (field_stats == nullptr) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"Failed to allocate memory for private data");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
		goto error;
	}

	field_stats->iterator = nullptr;
	field_stats->stats_value = bt_value_map_create();
	field_stats->event_class = nullptr;
	if (field_stats->stats_value == nullptr) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"Failed to allocate memory for field_stats.stats map");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
		goto error;
	}
	bt_self_component_set_data(bt_self_component_sink_as_self_component(self_component_sink),
				   field_stats);
	status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
	goto end;

error:
	if (field_stats) {
		free(field_stats);
	}
end:
	return status;
}

static bt_value_map_foreach_entry_const_func_status
stats_value_print_summary(const char *key, const bt_value *value, void *)
{
	assert(bt_value_is_map(value));

	const bt_value *min = bt_value_map_borrow_entry_value_const(value, "min");
	const bt_value *max = bt_value_map_borrow_entry_value_const(value, "max");
	const bt_value *display_base = bt_value_map_borrow_entry_value_const(value, "display_base");
	enum bt_field_class_integer_preferred_display_base display_base_value =
		BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_DECIMAL;

	if (display_base != nullptr) {
		display_base_value = (enum bt_field_class_integer_preferred_display_base)
			bt_value_integer_unsigned_get(display_base);
	}
	assert(min != nullptr);
	assert(max != nullptr);

	if (bt_value_is_string(min)) {
		fmt::print("{} \"{}\" \"{}\"\n",
			   key,
			   bt_value_string_get(min),
			   bt_value_string_get(max));
	} else if (bt_value_is_unsigned_integer(min)) {
		switch (display_base_value) {
		case BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL:
			fmt::print("{} 0x{:X} 0x{:X}\n",
				   key,
				   bt_value_integer_unsigned_get(min),
				   bt_value_integer_unsigned_get(max));
			break;
		default:
			fmt::print("{} {} {}\n",
				   key,
				   bt_value_integer_unsigned_get(min),
				   bt_value_integer_unsigned_get(max));
			break;
		}
	} else if (bt_value_is_signed_integer(min)) {
		switch (display_base_value) {
		case BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL:
			fmt::print("{} 0x{:X} 0x{:X}\n",
				   key,
				   (uint64_t) bt_value_integer_signed_get(min),
				   (uint64_t) bt_value_integer_signed_get(max));
			break;
		default:
			fmt::print("{} {} {}\n",
				   key,
				   bt_value_integer_signed_get(min),
				   bt_value_integer_signed_get(max));
			break;
		}
	} else if (bt_value_is_real(min)) {
		fmt::print("{} {:0g} {:0g}\n", key, bt_value_real_get(min), bt_value_real_get(max));
	} else {
		assert(BT_FALSE);
	}
	return BT_VALUE_MAP_FOREACH_ENTRY_CONST_FUNC_STATUS_OK;
}

void field_stats_finalize(bt_self_component_sink *self_component_sink)
{
	struct field_stats *field_stats = (struct field_stats *) bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink));
	bt_value_put_ref(field_stats->stats_value);
	free(field_stats);
}

bt_component_class_sink_graph_is_configured_method_status
field_stats_graph_is_configured(bt_self_component_sink *self_component_sink)
{
	struct field_stats *field_stats = (struct field_stats *) bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink));
	bt_self_component_port_input *input_port =
		bt_self_component_sink_borrow_input_port_by_index(self_component_sink, 0);
	if (bt_message_iterator_create_from_sink_component(
		    self_component_sink, input_port, &field_stats->iterator) !=
	    BT_MESSAGE_ITERATOR_CREATE_FROM_SINK_COMPONENT_STATUS_OK) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"input port message iterator creation failed");
		return BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_ERROR;
	}

	return BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_OK;
}

static bt_component_class_sink_consume_method_status
member_stats_set_min_max(bt_value *member_map,
			 const bt_field_class_structure_member *member,
			 const bt_field *member_field,
			 const bt_field_class *member_class,
			 const bt_field_class_type *member_class_type,
			 bt_self_component_sink *self_component_sink)
{
	bt_value *min, *max, *display_base = bt_value_null;
	const char *name = bt_field_class_structure_member_get_name(member);

	if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER)) {
		min = bt_value_integer_unsigned_create_init(
			bt_field_integer_unsigned_get_value(member_field));
		max = bt_value_integer_unsigned_create_init(
			bt_field_integer_unsigned_get_value(member_field));
		display_base = bt_value_integer_unsigned_create_init(
			bt_field_class_integer_get_preferred_display_base(member_class));
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER)) {
		min = bt_value_integer_signed_create_init(
			bt_field_integer_signed_get_value(member_field));
		max = bt_value_integer_signed_create_init(
			bt_field_integer_signed_get_value(member_field));
		display_base = bt_value_integer_unsigned_create_init(
			bt_field_class_integer_get_preferred_display_base(member_class));
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_STRING)) {
		min = bt_value_string_create_init(bt_field_string_get_value(member_field));
		max = bt_value_string_create_init(bt_field_string_get_value(member_field));
	} else if (bt_field_class_type_is(*member_class_type,
					  BT_FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL)) {
		min = bt_value_real_create_init(
			bt_field_real_double_precision_get_value(member_field));
		max = bt_value_real_create_init(
			bt_field_real_double_precision_get_value(member_field));
	} else if (bt_field_class_type_is(*member_class_type,
					  BT_FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL)) {
		min = bt_value_real_create_init(
			bt_field_real_single_precision_get_value(member_field));
		max = bt_value_real_create_init(
			bt_field_real_single_precision_get_value(member_field));
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_BIT_ARRAY)) {
		min = bt_value_integer_unsigned_create_init(
			bt_field_bit_array_get_value_as_integer(member_field));
		max = bt_value_integer_unsigned_create_init(
			bt_field_bit_array_get_value_as_integer(member_field));
	} else {
		const auto field_class_type_name = fmt::to_string(*member_class_type);

		fmt::print("Unsupported field type for '{}': {}\n", name, field_class_type_name);
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"Unsupported field type '%s' for member '%s'",
			field_class_type_name.c_str(),
			name);

		return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
	}

	if (min != nullptr) {
		bt_value_map_insert_entry(member_map, "min", min);
		bt_value_put_ref(min);
	} else {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"No minimum value for member '%s'",
			name);
		return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
	}
	if (max != nullptr) {
		bt_value_map_insert_entry(member_map, "max", max);
		bt_value_put_ref(max);
	} else {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"No maximum value for member '%s'",
			name);
		return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
	}
	if (display_base != bt_value_null) {
		bt_value_map_insert_entry(member_map, "display_base", display_base);
		bt_value_put_ref(display_base);
	}
	return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
}

static bt_component_class_sink_consume_method_status
member_stats_update_min_max(bt_value *member_map,
			    const bt_field_class_structure_member *member,
			    const bt_field *member_field,
			    const bt_field_class_type *member_class_type,
			    bt_self_component_sink *self_component_sink)
{
	const char *name = bt_field_class_structure_member_get_name(member);
	bt_value *min = bt_value_map_borrow_entry_value(member_map, "min");
	bt_value *max = bt_value_map_borrow_entry_value(member_map, "max");

	if (min == nullptr || max == nullptr) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"Missing min or max value for member '%s'",
			name);
		return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
	}

	if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER)) {
		bt_value *value = bt_value_integer_unsigned_create_init(
			bt_field_integer_unsigned_get_value(member_field));
		if (bt_value_integer_unsigned_get(value) < bt_value_integer_unsigned_get(min)) {
			bt_value_integer_unsigned_set(min, bt_value_integer_unsigned_get(value));
		}
		if (bt_value_integer_unsigned_get(value) > bt_value_integer_unsigned_get(max)) {
			bt_value_integer_unsigned_set(max, bt_value_integer_unsigned_get(value));
		}
		bt_value_put_ref(value);
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER)) {
		bt_value *value = bt_value_integer_signed_create_init(
			bt_field_integer_signed_get_value(member_field));
		if (bt_value_integer_signed_get(value) < bt_value_integer_signed_get(min)) {
			bt_value_integer_signed_set(min, bt_value_integer_signed_get(value));
		}
		if (bt_value_integer_signed_get(value) > bt_value_integer_signed_get(max)) {
			bt_value_integer_signed_set(max, bt_value_integer_signed_get(value));
		}
		bt_value_put_ref(value);
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_STRING)) {
		bt_value *value =
			bt_value_string_create_init(bt_field_string_get_value(member_field));
		if (strcmp(bt_value_string_get(value), bt_value_string_get(min)) < 0) {
			bt_value_string_set(min, bt_value_string_get(value));
		}
		if (strcmp(bt_value_string_get(value), bt_value_string_get(max)) > 0) {
			bt_value_string_set(max, bt_value_string_get(value));
		}
		bt_value_put_ref(value);
	} else if (bt_field_class_type_is(*member_class_type,
					  BT_FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL)) {
		bt_value *value = bt_value_real_create_init(
			bt_field_real_double_precision_get_value(member_field));
		if (bt_value_real_get(value) < bt_value_real_get(min)) {
			bt_value_real_set(min, bt_value_real_get(value));
		}
		if (bt_value_real_get(value) > bt_value_real_get(max)) {
			bt_value_real_set(max, bt_value_real_get(value));
		}
		bt_value_put_ref(value);
	} else if (bt_field_class_type_is(*member_class_type,
					  BT_FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL)) {
		bt_value *value = bt_value_real_create_init(
			(double) bt_field_real_single_precision_get_value(member_field));
		if (bt_value_real_get(value) < bt_value_real_get(min)) {
			bt_value_real_set(min, bt_value_real_get(value));
		}
		if (bt_value_real_get(value) > bt_value_real_get(max)) {
			bt_value_real_set(max, bt_value_real_get(value));
		}
		bt_value_put_ref(value);
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_BIT_ARRAY)) {
		bt_value *value = bt_value_integer_unsigned_create_init(
			bt_field_bit_array_get_value_as_integer(member_field));
		if (bt_value_integer_unsigned_get(value) < bt_value_integer_unsigned_get(min)) {
			bt_value_integer_unsigned_set(min, bt_value_integer_unsigned_get(value));
		}
		if (bt_value_integer_unsigned_get(value) > bt_value_integer_unsigned_get(max)) {
			bt_value_integer_unsigned_set(max, bt_value_integer_unsigned_get(value));
		}
		bt_value_put_ref(value);
	} else {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"Unsupported field type '%ld' for member '%s'",
			*member_class_type,
			name);
		return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
	}
	return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
}

static bt_component_class_sink_consume_method_status
update_stats(const bt_message *message,
	     field_stats *field_stats,
	     bt_self_component_sink *self_component_sink)
{
	if (bt_message_get_type(message) != BT_MESSAGE_TYPE_EVENT) {
		/* It's not an error to get non-EVENT messages */
		return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
	}

	bt_component_class_sink_consume_method_status status;
	const bt_event *event = bt_message_event_borrow_event_const(message);
	const bt_field *event_payload = bt_event_borrow_payload_field_const(event);
	const bt_event_class *event_class = bt_event_borrow_class_const(event);
	const bt_field_class *event_payload_class =
		bt_event_class_borrow_payload_field_class_const(event_class);

	if (field_stats->event_class != nullptr) {
		assert(event_class == field_stats->event_class);
	} else {
		field_stats->event_class = event_class;
	}

	/* Iterate over each field in the event payload */
	for (uint64_t index = 0;
	     index < bt_field_class_structure_get_member_count(event_payload_class);
	     index++) {
		const bt_field_class_structure_member *member =
			bt_field_class_structure_borrow_member_by_index_const(event_payload_class,
									      index);
		const char *name = bt_field_class_structure_member_get_name(member);
		const bt_field *member_field =
			bt_field_structure_borrow_member_field_by_name_const(event_payload, name);
		const bt_field_class *member_class =
			bt_field_class_structure_member_borrow_field_class_const(member);
		const bt_field_class_type member_class_type = bt_field_class_get_type(member_class);

		/* Ignore array and structure field types. */
		if (bt_field_class_type_is(member_class_type, BT_FIELD_CLASS_TYPE_ARRAY) ||
		    bt_field_class_type_is(member_class_type, BT_FIELD_CLASS_TYPE_STRUCTURE)) {
			continue;
		}

		bt_value *member_map =
			bt_value_map_borrow_entry_value(field_stats->stats_value, name);
		if (member_map == nullptr) {
			if (bt_value_map_insert_empty_map_entry(
				    field_stats->stats_value, name, &member_map) !=
			    BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
				BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
					bt_self_component_sink_as_self_component(
						self_component_sink),
					"Failed to insert new empty map entry for field '%s'",
					name);
				return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
			}

			status = member_stats_set_min_max(member_map,
							  member,
							  member_field,
							  member_class,
							  &member_class_type,
							  self_component_sink);
			if (status != BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK) {
				return status;
			}
		} else {
			status = member_stats_update_min_max(member_map,
							     member,
							     member_field,
							     &member_class_type,
							     self_component_sink);
			if (status != BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK) {
				return status;
			}
		}
	}
	return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
}

bt_component_class_sink_consume_method_status
field_stats_consume(bt_self_component_sink *self_component_sink)
{
	bt_component_class_sink_consume_method_status status;
	struct field_stats *field_stats = (struct field_stats *) bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink));
	bt_message_array_const messages;
	uint64_t message_count;
	bt_message_iterator_next_status next_status;

	assert(field_stats);
	next_status = bt_message_iterator_next(field_stats->iterator, &messages, &message_count);

	if (next_status != BT_MESSAGE_ITERATOR_NEXT_STATUS_OK) {
		if (next_status == BT_MESSAGE_ITERATOR_NEXT_STATUS_END) {
			bt_value_map_foreach_entry_const(
				field_stats->stats_value, stats_value_print_summary, nullptr);
			bt_message_iterator_put_ref(field_stats->iterator);
		}
		status = static_cast<bt_component_class_sink_consume_method_status>(next_status);
		goto end;
	}

	for (uint64_t index = 0; index < message_count; index++) {
		const bt_message *message = messages[index];
		status = update_stats(message, field_stats, self_component_sink);
		bt_message_put_ref(message);
		if (status != BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK) {
			goto end;
		}
	}
	status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
end:
	return status;
}
