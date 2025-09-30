/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_CTL_MEMORY_HPP
#define LTTNG_COMMON_CTL_MEMORY_HPP

#include "lttng/handle.h"

#include <common/container-wrapper.hpp>
#include <common/meta-helpers.hpp>

#include <lttng/lttng.h>

#include <memory>

namespace lttng {
namespace ctl {

using event_rule_uptr = std::unique_ptr<
	lttng_event_rule,
	lttng::memory::create_deleter_class<lttng_event_rule, lttng_event_rule_destroy>>;

using kernel_location_uptr =
	std::unique_ptr<lttng_kernel_probe_location,
			lttng::memory::create_deleter_class<lttng_kernel_probe_location,
							    lttng_kernel_probe_location_destroy>>;

using notification_uptr = std::unique_ptr<
	lttng_notification,
	lttng::memory::create_deleter_class<lttng_notification, lttng_notification_destroy>>;

using data_stream_info_sets_cuptr =
	std::unique_ptr<const lttng_data_stream_info_sets,
			lttng::memory::create_deleter_class<const lttng_data_stream_info_sets,
							    lttng_data_stream_info_sets_destroy>>;

using handle_uptr =
	std::unique_ptr<lttng_handle,
			lttng::memory::create_deleter_class<lttng_handle, lttng_destroy_handle>>;

using lttng_session_uptr = std::unique_ptr<
	lttng_session[],
	lttng::memory::create_deleter_class<lttng_session, lttng::memory::free>::deleter>;

using lttng_channel_uptr = std::unique_ptr<
	lttng_channel[],
	lttng::memory::create_deleter_class<lttng_channel, lttng::memory::free>::deleter>;

namespace details {
template <typename WrappedTypeUniquePtr>
class c_array_storage {
public:
	using pointer = typename WrappedTypeUniquePtr::pointer;

	c_array_storage(pointer raw_elements, std::size_t element_count) :
		_array(raw_elements), _count(element_count)
	{
	}

	c_array_storage(c_array_storage&& original) noexcept :
		_array(std::move(original._array)), _count(original._count)
	{
	}

	c_array_storage(c_array_storage&& original, std::size_t new_count) :
		_array(std::move(original._array)), _count(new_count)
	{
	}

	c_array_storage(c_array_storage&) = delete;
	c_array_storage& operator=(const c_array_storage& other) = delete;
	c_array_storage& operator=(c_array_storage&& other) = delete;
	~c_array_storage() = default;

	WrappedTypeUniquePtr _array;
	std::size_t _count = 0;
};

template <typename WrappedTypeUniquePtr>
class c_array_storage_operations {
public:
	static typename WrappedTypeUniquePtr::element_type&
	get(const lttng::ctl::details::c_array_storage<WrappedTypeUniquePtr>& storage,
	    std::size_t index) noexcept
	{
		return storage._array[index];
	}

	static std::size_t
	size(const lttng::ctl::details::c_array_storage<WrappedTypeUniquePtr>& storage)
	{
		return storage._count;
	}
};

template <typename ListElementType, typename ListStorageType, typename ListOperations>
class element_list : public lttng::utils::random_access_container_wrapper<ListStorageType,
									  ListElementType&,
									  ListOperations> {
public:
	friend ListOperations;

	element_list() :
		lttng::utils::random_access_container_wrapper<ListStorageType,
							      ListElementType&,
							      ListOperations>({ nullptr, 0 })
	{
	}

	element_list(element_list&& original) noexcept :
		lttng::utils::random_access_container_wrapper<ListStorageType,
							      ListElementType&,
							      ListOperations>(
			std::move(original._container))
	{
	}

	element_list(element_list&& original, std::size_t new_count) :
		lttng::utils::random_access_container_wrapper<ListStorageType,
							      ListElementType&,
							      ListOperations>(
			{ std::move(original._container), new_count })
	{
	}

	element_list(ListElementType *raw_elements, std::size_t raw_element_count) :
		lttng::utils::random_access_container_wrapper<ListStorageType,
							      ListElementType&,
							      ListOperations>(
			{ raw_elements, raw_element_count })
	{
	}

	element_list(element_list&) = delete;
	element_list& operator=(const element_list& other) = delete;
	element_list& operator=(element_list&& other) = delete;
	~element_list() = default;

	void shrink(std::size_t new_size) noexcept
	{
		LTTNG_ASSERT(new_size <= this->_container._count);
		this->_container._count = new_size;
	}
};

using session_list_storage = c_array_storage<lttng_session_uptr>;
using session_list_operations = c_array_storage_operations<lttng_session_uptr>;

using channel_list_storage = c_array_storage<lttng_channel_uptr>;
using channel_list_operations = c_array_storage_operations<lttng_channel_uptr>;

} /* namespace details */

using session_list = details::element_list<lttng_session,
					   details::session_list_storage,
					   details::session_list_operations>;

using channel_list = details::element_list<lttng_channel,
					   details::channel_list_storage,
					   details::channel_list_operations>;

} /* namespace ctl */
} /* namespace lttng */

#endif /* LTTNG_COMMON_CTL_MEMORY_HPP */
