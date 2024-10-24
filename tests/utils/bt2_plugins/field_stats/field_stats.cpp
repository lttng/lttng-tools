/*
 * Copyright (C) 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "../fmt.hpp"
#include "../utils.hpp"
#include "field_stats.hpp"

#include <common/make-unique-wrapper.hpp>
#include <common/make-unique.hpp>

#include <assert.h>
#include <babeltrace2/babeltrace.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <utility>

class bad_alloc_with_msg : public std::bad_alloc {
public:
	explicit bad_alloc_with_msg(std::string msg) : _msg(std::move(msg))
	{
	}

	const char *what() const noexcept override
	{
		return _msg.c_str();
	}

private:
	std::string _msg;
};

struct field_stats {
public:
	field_stats() : stats_value{ lttng::bt2::make_value_ref(bt_value_map_create()) }
	{
		if (!stats_value) {
			throw bad_alloc_with_msg(
				"Failed to allocate memory for field_stats.stats map");
		}
	}

	~field_stats() = default;

	lttng::bt2::message_iterator_ref upstream_iterator;
	lttng::bt2::event_class_const_ref event_class;
	const lttng::bt2::value_ref stats_value;
};

namespace {
bt_value_map_foreach_entry_const_func_status
stats_value_print_summary(const char *key, const bt_value *value, void *)
{
	LTTNG_ASSERT(bt_value_is_map(value));

	const auto *min = bt_value_map_borrow_entry_value_const(value, "min");
	LTTNG_ASSERT(min != nullptr);
	const auto *max = bt_value_map_borrow_entry_value_const(value, "max");
	LTTNG_ASSERT(max != nullptr);

	const auto *display_base = bt_value_map_borrow_entry_value_const(value, "display_base");
	auto display_base_value = BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_DECIMAL;

	if (display_base != nullptr) {
		display_base_value = (enum bt_field_class_integer_preferred_display_base)
			bt_value_integer_unsigned_get(display_base);
	}

	LTTNG_ASSERT(bt_value_get_type(min) == bt_value_get_type(max));

	switch (bt_value_get_type(min)) {
	case BT_VALUE_TYPE_STRING:
		fmt::print("{} \"{}\" \"{}\"\n",
			   key,
			   bt_value_string_get(min),
			   bt_value_string_get(max));
		break;
	case BT_VALUE_TYPE_UNSIGNED_INTEGER:
		switch (display_base_value) {
		case BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL:
			std::cout << lttng::format("{} 0x{:X} 0x{:X}\n",
						   key,
						   bt_value_integer_unsigned_get(min),
						   bt_value_integer_unsigned_get(max));
			break;
		default:
			std::cout << lttng::format("{} {} {}\n",
						   key,
						   bt_value_integer_unsigned_get(min),
						   bt_value_integer_unsigned_get(max));
			break;
		}

		break;
	case BT_VALUE_TYPE_SIGNED_INTEGER:
		switch (display_base_value) {
		case BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL:
			std::cout << lttng::format("{} 0x{:X} 0x{:X}\n",
						   key,
						   std::uint64_t(bt_value_integer_signed_get(min)),
						   std::uint64_t(bt_value_integer_signed_get(max)));
			break;
		default:
			std::cout << lttng::format("{} {} {}\n",
						   key,
						   bt_value_integer_signed_get(min),
						   bt_value_integer_signed_get(max));
			break;
		}

		break;
	case BT_VALUE_TYPE_REAL:
		std::cout << lttng::format(
			"{} {:0g} {:0g}\n", key, bt_value_real_get(min), bt_value_real_get(max));
		break;
	default:
		abort();
	}

	return BT_VALUE_MAP_FOREACH_ENTRY_CONST_FUNC_STATUS_OK;
}

void member_stats_set_min_max(bt_value *member_map,
			      const bt_field_class_structure_member *member,
			      const bt_field *member_field,
			      const bt_field_class *member_class,
			      const bt_field_class_type *member_class_type)
{
	lttng::bt2::value_ref min, max, display_base;
	const char *name = bt_field_class_structure_member_get_name(member);

	if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER)) {
		min = lttng::bt2::make_value_ref(bt_value_integer_unsigned_create_init(
			bt_field_integer_unsigned_get_value(member_field)));
		max = lttng::bt2::make_value_ref(bt_value_integer_unsigned_create_init(
			bt_field_integer_unsigned_get_value(member_field)));
		display_base = lttng::bt2::make_value_ref(bt_value_integer_unsigned_create_init(
			bt_field_class_integer_get_preferred_display_base(member_class)));
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER)) {
		min = lttng::bt2::make_value_ref(bt_value_integer_signed_create_init(
			bt_field_integer_signed_get_value(member_field)));
		max = lttng::bt2::make_value_ref(bt_value_integer_signed_create_init(
			bt_field_integer_signed_get_value(member_field)));
		display_base = lttng::bt2::make_value_ref(bt_value_integer_unsigned_create_init(
			bt_field_class_integer_get_preferred_display_base(member_class)));
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_STRING)) {
		min = lttng::bt2::make_value_ref(
			bt_value_string_create_init(bt_field_string_get_value(member_field)));
		max = lttng::bt2::make_value_ref(
			bt_value_string_create_init(bt_field_string_get_value(member_field)));
	} else if (bt_field_class_type_is(*member_class_type,
					  BT_FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL)) {
		min = lttng::bt2::make_value_ref(bt_value_real_create_init(
			bt_field_real_double_precision_get_value(member_field)));
		max = lttng::bt2::make_value_ref(bt_value_real_create_init(
			bt_field_real_double_precision_get_value(member_field)));
	} else if (bt_field_class_type_is(*member_class_type,
					  BT_FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL)) {
		min = lttng::bt2::make_value_ref(bt_value_real_create_init(
			bt_field_real_single_precision_get_value(member_field)));
		max = lttng::bt2::make_value_ref(bt_value_real_create_init(
			bt_field_real_single_precision_get_value(member_field)));
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_BIT_ARRAY)) {
		min = lttng::bt2::make_value_ref(bt_value_integer_unsigned_create_init(
			bt_field_bit_array_get_value_as_integer(member_field)));
		max = lttng::bt2::make_value_ref(bt_value_integer_unsigned_create_init(
			bt_field_bit_array_get_value_as_integer(member_field)));
	} else {
		throw std::runtime_error(lttng::format(
			"Unsupported field type '{}' for member '{}'", *member_class_type, name));
	}

	if (min) {
		bt_value_map_insert_entry(member_map, "min", min.get());
	} else {
		throw std::runtime_error(lttng::format("No minimum value for member '{}'", name));
	}

	if (max) {
		bt_value_map_insert_entry(member_map, "max", max.get());
	} else {
		throw std::runtime_error(lttng::format("No maximum value for member '{}'", name));
	}

	if (display_base) {
		bt_value_map_insert_entry(member_map, "display_base", display_base.get());
	}
}

void member_stats_update_min_max(bt_value *member_map,
				 const bt_field_class_structure_member *member,
				 const bt_field *member_field,
				 const bt_field_class_type *member_class_type)
{
	const char *name = bt_field_class_structure_member_get_name(member);
	bt_value *min = bt_value_map_borrow_entry_value(member_map, "min");
	bt_value *max = bt_value_map_borrow_entry_value(member_map, "max");

	if (min == nullptr || max == nullptr) {
		throw std::runtime_error(
			lttng::format("Missing min or max value for member '{}'", name));
	}

	if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER)) {
		const auto value = bt_field_integer_unsigned_get_value(member_field);

		if (value < bt_value_integer_unsigned_get(min)) {
			bt_value_integer_unsigned_set(min, value);
		}

		if (value > bt_value_integer_unsigned_get(max)) {
			bt_value_integer_unsigned_set(max, value);
		}
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER)) {
		const auto value = bt_field_integer_signed_get_value(member_field);

		if (value < bt_value_integer_signed_get(min)) {
			bt_value_integer_signed_set(min, value);
		}

		if (value > bt_value_integer_signed_get(max)) {
			bt_value_integer_signed_set(max, value);
		}
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_STRING)) {
		const auto value = bt_field_string_get_value(member_field);

		if (strcmp(value, bt_value_string_get(min)) < 0) {
			bt_value_string_set(min, value);
		}

		if (strcmp(value, bt_value_string_get(max)) > 0) {
			bt_value_string_set(max, value);
		}
	} else if (bt_field_class_type_is(*member_class_type,
					  BT_FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL)) {
		const auto value = bt_field_real_double_precision_get_value(member_field);

		if (value < bt_value_real_get(min)) {
			bt_value_real_set(min, value);
		}

		if (value > bt_value_real_get(max)) {
			bt_value_real_set(max, value);
		}
	} else if (bt_field_class_type_is(*member_class_type,
					  BT_FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL)) {
		const auto value = double(bt_field_real_single_precision_get_value(member_field));

		if (value < bt_value_real_get(min)) {
			bt_value_real_set(min, value);
		}

		if (value > bt_value_real_get(max)) {
			bt_value_real_set(max, value);
		}
	} else if (bt_field_class_type_is(*member_class_type, BT_FIELD_CLASS_TYPE_BIT_ARRAY)) {
		const auto value = bt_field_bit_array_get_value_as_integer(member_field);

		if (value < bt_value_integer_unsigned_get(min)) {
			bt_value_integer_unsigned_set(min, value);
		}

		if (value > bt_value_integer_unsigned_get(max)) {
			bt_value_integer_unsigned_set(max, value);
		}
	} else {
		throw std::runtime_error(lttng::format(
			"Unsupported field type '%{}' for member '{}'", *member_class_type, name));
	}
}

bt_component_class_sink_consume_method_status
update_stats(const bt_message *message,
	     field_stats& field_stats,
	     bt_self_component_sink *self_component_sink)
{
	if (bt_message_get_type(message) != BT_MESSAGE_TYPE_EVENT) {
		/* It's not an error to get non-EVENT messages. */
		return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
	}

	const auto *event = bt_message_event_borrow_event_const(message);
	const auto *event_payload = bt_event_borrow_payload_field_const(event);
	const auto *event_class = bt_event_borrow_class_const(event);
	const auto *event_payload_class =
		bt_event_class_borrow_payload_field_class_const(event_class);

	if (field_stats.event_class != nullptr) {
		LTTNG_ASSERT(event_class == field_stats.event_class.get());
	} else {
		bt_event_class_get_ref(event_class);
		field_stats.event_class.reset(event_class);
	}

	/* Iterate over each field in the event payload */
	for (std::uint64_t index = 0;
	     index < bt_field_class_structure_get_member_count(event_payload_class);
	     index++) {
		const bt_field_class_structure_member *member =
			bt_field_class_structure_borrow_member_by_index_const(event_payload_class,
									      index);
		const auto *name = bt_field_class_structure_member_get_name(member);
		const auto *member_field =
			bt_field_structure_borrow_member_field_by_name_const(event_payload, name);
		const auto *member_class =
			bt_field_class_structure_member_borrow_field_class_const(member);
		const auto member_class_type = bt_field_class_get_type(member_class);

		if (bt_field_class_type_is(member_class_type, BT_FIELD_CLASS_TYPE_ARRAY) ||
		    bt_field_class_type_is(member_class_type, BT_FIELD_CLASS_TYPE_STRUCTURE)) {
			/* Ignore array and structure field types. */
			continue;
		}

		try {
			auto *member_map = bt_value_map_borrow_entry_value(
				field_stats.stats_value.get(), name);
			if (member_map == nullptr) {
				/* Initial creation of the value. */
				if (bt_value_map_insert_empty_map_entry(
					    field_stats.stats_value.get(), name, &member_map) !=
				    BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
					throw std::runtime_error(lttng::format(
						"Failed to insert new empty map entry for field '{}'",
						name));
				}

				member_stats_set_min_max(member_map,
							 member,
							 member_field,
							 member_class,
							 &member_class_type);
			} else {
				/* Update the value with min/max values. */
				member_stats_update_min_max(
					member_map, member, member_field, &member_class_type);
			}
		} catch (const std::exception& ex) {
			BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
				bt_self_component_sink_as_self_component(self_component_sink),
				"%s",
				ex.what());
			return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
		}
	}

	return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
}
} /* namespace */

bt_component_class_initialize_method_status
field_stats_initialize(bt_self_component_sink *self_component_sink,
		       bt_self_component_sink_configuration *,
		       const bt_value *,
		       void *)
{
	if (bt_self_component_sink_add_input_port(self_component_sink, "in", nullptr, nullptr) !=
	    BT_SELF_COMPONENT_ADD_PORT_STATUS_OK) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"Failed to add input port");
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	std::unique_ptr<struct field_stats> field_stats;
	try {
		field_stats = lttng::make_unique<struct field_stats>();
	} catch (const bad_alloc_with_msg& ex) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"%s",
			ex.what());
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
	} catch (const std::bad_alloc&) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"Failed to allocate memory for private data");
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
	}

	/* Transfer ownership to the component. */
	bt_self_component_set_data(bt_self_component_sink_as_self_component(self_component_sink),
				   field_stats.release());
	return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

void field_stats_finalize(bt_self_component_sink *self_component_sink)
{
	auto *field_stats = static_cast<struct field_stats *>(bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink)));

	delete field_stats;
}

bt_component_class_sink_graph_is_configured_method_status
field_stats_graph_is_configured(bt_self_component_sink *self_component_sink)
{
	auto& field_stats = *static_cast<struct field_stats *>(bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink)));
	auto *input_port =
		bt_self_component_sink_borrow_input_port_by_index(self_component_sink, 0);

	bt_message_iterator *raw_iterator;
	if (bt_message_iterator_create_from_sink_component(
		    self_component_sink, input_port, &raw_iterator) !=
	    BT_MESSAGE_ITERATOR_CREATE_FROM_SINK_COMPONENT_STATUS_OK) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_sink_as_self_component(self_component_sink),
			"input port message iterator creation failed");
		return BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_ERROR;
	}

	field_stats.upstream_iterator.reset(raw_iterator);
	return BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_OK;
}

bt_component_class_sink_consume_method_status
field_stats_consume(bt_self_component_sink *self_component_sink)
{
	auto& field_stats = *static_cast<struct field_stats *>(bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink)));

	std::uint64_t message_count;
	bt_message_array_const messages;
	const auto next_status = bt_message_iterator_next(
		field_stats.upstream_iterator.get(), &messages, &message_count);

	if (next_status != BT_MESSAGE_ITERATOR_NEXT_STATUS_OK) {
		if (next_status == BT_MESSAGE_ITERATOR_NEXT_STATUS_END) {
			/* End reached, print the summary. */
			bt_value_map_foreach_entry_const(
				field_stats.stats_value.get(), stats_value_print_summary, nullptr);
		}

		return static_cast<bt_component_class_sink_consume_method_status>(next_status);
	}

	for (std::uint64_t index = 0; index < message_count; index++) {
		const auto message = lttng::bt2::message_const_ref(messages[index]);

		const auto status = update_stats(message.get(), field_stats, self_component_sink);
		if (status != BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK) {
			return status;
		}
	}

	return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
}
