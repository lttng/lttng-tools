/*
 * Copyright (C) 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "event_name.hpp"

#include <assert.h>
#include <babeltrace2/babeltrace.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unordered_set>

struct event_name {
	std::unordered_set<std::string> names;
	const bt_value *names_value;
	/* weak reference */
	bt_self_component_port_input *input_port;
};

struct event_name_iterator_data {
	struct event_name *event_name;
	bt_message_iterator *iterator;
};

bt_component_class_initialize_method_status
event_name_initialize(bt_self_component_filter *self_comp,
		      bt_self_component_filter_configuration *,
		      const bt_value *params,
		      void *)
{
	bt_component_class_initialize_method_status status;
	bt_self_component_port_input *input_port;
	struct event_name *event_name;
	auto self = bt_self_component_filter_as_self_component(self_comp);
	if (bt_self_component_filter_add_input_port(self_comp, "in", nullptr, &input_port) !=
	    BT_SELF_COMPONENT_ADD_PORT_STATUS_OK) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(self,
								    "Failed to add input port");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
		goto end;
	}

	if (bt_self_component_filter_add_output_port(self_comp, "out", nullptr, nullptr) !=
	    BT_SELF_COMPONENT_ADD_PORT_STATUS_OK) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(self,
								    "Failed to add output port");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
		goto end;
	}

	event_name = new (std::nothrow) struct event_name;
	if (event_name == nullptr) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			self, "Failed to allocate memory for private component data");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
		goto end;
	}

	event_name->input_port = input_port;
	event_name->names_value = bt_value_map_borrow_entry_value_const(params, "names");
	if (event_name->names_value == nullptr) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			self, "'names' parameter is required");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
		goto err_free;
	}
	if (bt_value_get_type(event_name->names_value) != BT_VALUE_TYPE_ARRAY) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			self, "'names' parameter must be an array");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
		goto err_free;
	}
	if (bt_value_array_is_empty(event_name->names_value)) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			bt_self_component_filter_as_self_component(self_comp),
			"'names' parameter must not be empty");
		status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
		goto err_free;
	}
	for (uint64_t index = 0; index < bt_value_array_get_length(event_name->names_value);
	     index++) {
		const bt_value *names_entry = bt_value_array_borrow_element_by_index_const(
			event_name->names_value, index);
		if (bt_value_get_type(names_entry) != BT_VALUE_TYPE_STRING) {
			BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
				self, "All members of the 'names' parameter array must be strings");
			status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
			goto err_free;
		}
		event_name->names.emplace(bt_value_string_get(names_entry));
	}
	bt_value_get_ref(event_name->names_value);
	bt_self_component_set_data(self, event_name);
	status = BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
	goto end;

err_free:
	delete event_name;
end:
	return status;
}

void event_name_finalize(bt_self_component_filter *self_comp)
{
	struct event_name *event_name = (struct event_name *) bt_self_component_get_data(
		bt_self_component_filter_as_self_component(self_comp));
	bt_value_put_ref(event_name->names_value);
	delete event_name;
}

bt_message_iterator_class_initialize_method_status
event_name_message_iterator_initialize(bt_self_message_iterator *self_message_iterator,
				       bt_self_message_iterator_configuration *,
				       bt_self_component_port_output *)
{
	struct event_name *event_name = (struct event_name *) bt_self_component_get_data(
		bt_self_message_iterator_borrow_component(self_message_iterator));
	assert(event_name);

	struct event_name_iterator_data *iter_data =
		(struct event_name_iterator_data *) malloc(sizeof(struct event_name_iterator_data));

	if (iter_data == nullptr) {
		return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}
	iter_data->event_name = event_name;

	if (bt_message_iterator_create_from_message_iterator(
		    self_message_iterator, event_name->input_port, &iter_data->iterator) !=
	    BT_MESSAGE_ITERATOR_CREATE_FROM_MESSAGE_ITERATOR_STATUS_OK) {
		free(iter_data);
		return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	bt_self_message_iterator_set_data(self_message_iterator, iter_data);

	return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

void event_name_message_iterator_finalize(bt_self_message_iterator *self_message)
{
	struct event_name_iterator_data *iter_data =
		(struct event_name_iterator_data *) bt_self_message_iterator_get_data(self_message);

	assert(iter_data);
	bt_message_iterator_put_ref(iter_data->iterator);
	free(iter_data);
}

static bool message_passes(const bt_message *message, const std::unordered_set<std::string>& names)
{
	if (bt_message_get_type(message) != BT_MESSAGE_TYPE_EVENT) {
		return true;
	}

	const bt_event *event = bt_message_event_borrow_event_const(message);
	const bt_event_class *event_class = bt_event_borrow_class_const(event);
	const char *event_name = bt_event_class_get_name(event_class);

	if (event_name == nullptr) {
		return false;
	}

	if (names.find(event_name) != names.end()) {
		return true;
	}

	return false;
}

bt_message_iterator_class_next_method_status
event_name_message_iterator_next(bt_self_message_iterator *self_message_iterator,
				 bt_message_array_const messages,
				 uint64_t,
				 uint64_t *count)
{
	bt_message_array_const upstream_messages;
	uint64_t upstream_message_count;
	uint64_t index = 0;
	bt_message_iterator_next_status next_status;
	bt_message_iterator_class_next_method_status status =
		BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
	struct event_name_iterator_data *iter_data =
		(struct event_name_iterator_data *) bt_self_message_iterator_get_data(
			self_message_iterator);
	struct event_name *event_name = (struct event_name *) bt_self_component_get_data(
		bt_self_message_iterator_borrow_component(self_message_iterator));

	assert(event_name);
	assert(iter_data);

	while (index == 0) {
		next_status = bt_message_iterator_next(
			iter_data->iterator, &upstream_messages, &upstream_message_count);
		if (next_status != BT_MESSAGE_ITERATOR_NEXT_STATUS_OK) {
			status = static_cast<bt_message_iterator_class_next_method_status>(
				next_status);
			goto end;
		}

		for (uint64_t upstream_index = 0; upstream_index < upstream_message_count;
		     upstream_index++) {
			const bt_message *upstream_message = upstream_messages[upstream_index];
			if (message_passes(upstream_message, event_name->names)) {
				messages[index] = upstream_message;
				index++;
			} else {
				bt_message_put_ref(upstream_message);
			}
		}
	}

	*count = index;
end:
	return status;
}
