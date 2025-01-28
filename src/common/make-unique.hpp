/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAKE_UNIQUE_H
#define LTTNG_MAKE_UNIQUE_H

#include <memory>

namespace lttng {

template <typename Type, typename... Args>
std::unique_ptr<Type> make_unique(Args&&...args)
{
	return std::unique_ptr<Type>(new Type(std::forward<Args>(args)...));
}

} /* namespace lttng */

#endif /* LTTNG_MAKE_UNIQUE_H */
