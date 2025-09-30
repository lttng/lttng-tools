/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-only
 *
 */

#ifndef LTTNG_CTL_DOMAIN_HPP
#define LTTNG_CTL_DOMAIN_HPP

#include <common/domain.hpp>

#include <lttng/lttng.h>

namespace lttng {
namespace ctl {

lttng_domain_type get_lttng_domain_type_from_domain_class(lttng::domain_class domain_class);

} /* namespace ctl */
} /* namespace lttng */

#endif /* LTTNG_CTL_DOMAIN_HPP */
