/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_CLOCK_CLASS_H
#define LTTNG_UST_CLOCK_CLASS_H

#include "clock-class.hpp"

namespace lttng {
namespace sessiond {
namespace ust {

class clock_class : public lttng::sessiond::trace::clock_class {
public:
	clock_class();
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_UST_CLOCK_CLASS_H */
