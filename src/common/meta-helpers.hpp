/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_META_HELPERS_HPP
#define LTTNG_META_HELPERS_HPP

#include <memory>

/*
 * Collection of meta-programming helpers.
 *
 * @see type-traits.hpp
 */
namespace lttng {
namespace memory {
template <typename WrappedType, void (*DeleterFunction)(WrappedType *)>
struct create_deleter_class {
	struct deleter {
		void operator()(WrappedType *instance) const
		{
			DeleterFunction(instance);
		}
	};

	std::unique_ptr<WrappedType, deleter> operator()(WrappedType *instance) const
	{
		return std::unique_ptr<WrappedType, deleter>(instance);
	}
};
} /* namespace memory */
} /* namespace lttng */

#endif /* LTTNG_META_HELPERS_HPP */
