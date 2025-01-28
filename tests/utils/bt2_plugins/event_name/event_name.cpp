/*
 * SPDX-FileCopyrightText: 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "../utils.hpp"
#include "event_name.hpp"

#include <common/container-wrapper.hpp>
#include <common/macros.hpp>
#include <common/make-unique.hpp>

#include <assert.h>
#include <babeltrace2/babeltrace.h>
#include <cstdint>
#include <exception>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unordered_set>

class event_name_set_operations {
public:
	static const char *get(const bt_value *array, std::size_t index)
	{
		const auto *names_entry =
			bt_value_array_borrow_element_by_index_const(array, index);

		if (bt_value_get_type(names_entry) != BT_VALUE_TYPE_STRING) {
			throw std::runtime_error(
				"All members of the 'names' parameter array must be strings");
		}

		return bt_value_string_get(names_entry);
	}

	static std::size_t size(const bt_value *array)
	{
		return bt_value_array_get_length(array);
	}
};

class event_name_set
	: public lttng::utils::random_access_container_wrapper<const bt_value *,
							       const char *,
							       event_name_set_operations> {
public:
	friend event_name_set_operations;

	event_name_set() :
		lttng::utils::random_access_container_wrapper<const bt_value *,
							      const char *,
							      event_name_set_operations>(nullptr)
	{
	}

	event_name_set(event_name_set&& original) noexcept :
		lttng::utils::random_access_container_wrapper<const bt_value *,
							      const char *,
							      event_name_set_operations>(
			original._container)
	{
	}

	explicit event_name_set(const bt_value *names) :
		lttng::utils::random_access_container_wrapper<const bt_value *,
							      const char *,
							      event_name_set_operations>(names)
	{
		if (bt_value_get_type(names) != BT_VALUE_TYPE_ARRAY) {
			throw std::invalid_argument("'names' parameter must be an array");
		}
	}
};

class event_name_filter {
public:
	event_name_filter(bt_self_component_port_input *input_port_,
			  const event_name_set& name_set) :
		input_port{ input_port_ }, _names{ name_set.begin(), name_set.end() }
	{
	}

	bool event_name_is_allowed(const char *event_name) const noexcept
	{
		return _names.find(event_name) != _names.end();
	}

	/* weak reference */
	bt_self_component_port_input *const input_port;

private:
	const std::unordered_set<std::string> _names;
};

struct event_name_iterator_data {
	event_name_iterator_data(lttng::bt2::message_iterator_ref iterator_,
				 const class event_name_filter& event_name_filter_) :
		upstream_iterator{ std::move(iterator_) }, event_name_filter{ event_name_filter_ }
	{
	}

	~event_name_iterator_data() = default;

	const lttng::bt2::message_iterator_ref upstream_iterator;
	const class event_name_filter& event_name_filter;
};

namespace {
bool message_passes(const bt_message *message, const event_name_filter& event_name_filter)
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

	return event_name_filter.event_name_is_allowed(event_name);
}
} /* namespace */

bt_component_class_initialize_method_status
event_name_initialize(bt_self_component_filter *self_comp,
		      bt_self_component_filter_configuration *,
		      const bt_value *params,
		      void *)
{
	bt_self_component_port_input *input_port;
	std::unique_ptr<class event_name_filter> event_name_filter;

	auto self = bt_self_component_filter_as_self_component(self_comp);
	if (bt_self_component_filter_add_input_port(self_comp, "in", nullptr, &input_port) !=
	    BT_SELF_COMPONENT_ADD_PORT_STATUS_OK) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(self,
								    "Failed to add input port");
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	if (bt_self_component_filter_add_output_port(self_comp, "out", nullptr, nullptr) !=
	    BT_SELF_COMPONENT_ADD_PORT_STATUS_OK) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(self,
								    "Failed to add output port");
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	const auto names_param = bt_value_map_borrow_entry_value_const(params, "names");
	if (names_param == nullptr) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			self, "'names' parameter is required");
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	try {
		const event_name_set event_names{ names_param };
		if (event_names.empty()) {
			BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
				bt_self_component_filter_as_self_component(self_comp),
				"'names' parameter must not be empty");
			return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
		}

		event_name_filter =
			lttng::make_unique<class event_name_filter>(input_port, event_names);
	} catch (const std::bad_alloc&) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(
			self, "Failed to allocate memory for private component data");
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
	} catch (const std::exception& ex) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(self, "%s", ex.what());
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	/* Ownership of event_name is transferred to the component. */
	bt_self_component_set_data(self, event_name_filter.release());
	return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

void event_name_finalize(bt_self_component_filter *self_comp)
{
	class event_name_filter *event_name_filter =
		(class event_name_filter *) bt_self_component_get_data(
			bt_self_component_filter_as_self_component(self_comp));

	delete event_name_filter;
}

bt_message_iterator_class_initialize_method_status
event_name_message_iterator_initialize(bt_self_message_iterator *self_message_iterator,
				       bt_self_message_iterator_configuration *,
				       bt_self_component_port_output *)
{
	const auto& event_name_filter =
		*static_cast<class event_name_filter *>(bt_self_component_get_data(
			bt_self_message_iterator_borrow_component(self_message_iterator)));

	bt_message_iterator *raw_iterator;
	if (bt_message_iterator_create_from_message_iterator(
		    self_message_iterator, event_name_filter.input_port, &raw_iterator) !=
	    BT_MESSAGE_ITERATOR_CREATE_FROM_MESSAGE_ITERATOR_STATUS_OK) {
		return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	lttng::bt2::message_iterator_ref iterator(raw_iterator);
	raw_iterator = nullptr;

	std::unique_ptr<event_name_iterator_data> iter_data;
	try {
		iter_data = lttng::make_unique<event_name_iterator_data>(std::move(iterator),
									 event_name_filter);
	} catch (const std::bad_alloc&) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_MESSAGE_ITERATOR(
			self_message_iterator, "Failed to allocate event_name iterator data");
		return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	/* Transfer the ownership of iter_data to the iterator. */
	bt_self_message_iterator_set_data(self_message_iterator, iter_data.release());
	return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

void event_name_message_iterator_finalize(bt_self_message_iterator *self_message)
{
	event_name_iterator_data *iter_data = static_cast<event_name_iterator_data *>(
		bt_self_message_iterator_get_data(self_message));

	LTTNG_ASSERT(iter_data);
	delete iter_data;
}

bt_message_iterator_class_next_method_status
event_name_message_iterator_next(bt_self_message_iterator *self_message_iterator,
				 bt_message_array_const messages_to_deliver_downstream,
				 uint64_t,
				 uint64_t *_messages_to_deliver_count)
{
	std::uint64_t messages_to_deliver_count = 0;
	auto *iter_data = static_cast<event_name_iterator_data *>(
		bt_self_message_iterator_get_data(self_message_iterator));
	const auto& event_name_filter =
		*static_cast<class event_name_filter *>(bt_self_component_get_data(
			bt_self_message_iterator_borrow_component(self_message_iterator)));

	LTTNG_ASSERT(iter_data);

	/* Retry until we have at least one message to deliver downstream. */
	while (messages_to_deliver_count == 0) {
		bt_message_array_const upstream_messages;
		bt_message_iterator_next_status next_status;
		uint64_t upstream_message_count;

		next_status = bt_message_iterator_next(iter_data->upstream_iterator.get(),
						       &upstream_messages,
						       &upstream_message_count);
		if (next_status != BT_MESSAGE_ITERATOR_NEXT_STATUS_OK) {
			return static_cast<bt_message_iterator_class_next_method_status>(
				next_status);
		}

		for (std::uint64_t upstream_index = 0; upstream_index < upstream_message_count;
		     upstream_index++) {
			lttng::bt2::message_const_ref upstream_message(
				upstream_messages[upstream_index]);

			if (message_passes(upstream_message.get(), event_name_filter)) {
				/* Reference transferred to downstream message batch. */
				messages_to_deliver_downstream[messages_to_deliver_count] =
					upstream_message.release();
				messages_to_deliver_count++;
			}
		}
	}

	*_messages_to_deliver_count = messages_to_deliver_count;
	return BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
}
