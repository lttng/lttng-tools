/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-app.hpp"
#include "ust-object-data.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>

#include <lttng/ust-ctl.h>
#include <lttng/ust-error.h>

#include <cstdlib>

namespace lsu = lttng::sessiond::ust;

lsu::ust_object_data::ust_object_data(lttng_ust_abi_object_data *data) noexcept : _obj(data)
{
}

lsu::ust_object_data::~ust_object_data()
{
	_cleanup();
}

lsu::ust_object_data::ust_object_data(ust_object_data&& other) noexcept : _obj(other._obj)
{
	other._obj = nullptr;
}

lsu::ust_object_data& lsu::ust_object_data::operator=(ust_object_data&& other) noexcept
{
	if (this != &other) {
		_cleanup();
		_obj = other._obj;
		other._obj = nullptr;
	}

	return *this;
}

lsu::ust_object_data lsu::ust_object_data::duplicate() const
{
	lttng_ust_abi_object_data *copy = nullptr;

	LTTNG_ASSERT(_obj);
	const auto ret = lttng_ust_ctl_duplicate_ust_object_data(&copy, _obj);
	if (ret < 0) {
		LTTNG_THROW_POSIX("Failed to duplicate UST object data", -ret);
	}

	return ust_object_data(copy);
}

lttng_ust_abi_object_data *lsu::ust_object_data::get() const noexcept
{
	return _obj;
}

lttng_ust_abi_object_data *lsu::ust_object_data::release() noexcept
{
	const auto data = _obj;
	_obj = nullptr;
	return data;
}

void lsu::ust_object_data::release_local_fds() noexcept
{
	if (!_obj) {
		return;
	}

	/*
	 * Passing -1 as the socket fd skips the tracer-side notification
	 * and only performs the per-type local cleanup (close FDs, free
	 * data blobs). The lttng-ust API zeroes the relevant fields on
	 * cleanup, so a subsequent call is a no-op for the local part and
	 * only sends RELEASE if a real fd is provided.
	 */
	const auto ret = lttng_ust_ctl_release_object(-1, _obj);
	if (ret < 0 && ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
		ERR_FMT("Failed to release UST object data: handle={}, ret={}",
			static_cast<void *>(_obj),
			ret);
	}
}

void lsu::ust_object_data::_cleanup() noexcept
{
	if (!_obj) {
		/* Was moved from. */
		return;
	}

	release_local_fds();
	free(_obj);
	_obj = nullptr;
}
