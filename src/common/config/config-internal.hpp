/*
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONFIG_CONFIG_INTERNAL_HPP
#define LTTNG_CONFIG_CONFIG_INTERNAL_HPP

#include <lttng/domain.h>

#include <vendor/optional.hpp>

#include <libxml/xmlwriter.h>
#include <stdio.h>

struct config_writer {
	xmlTextWriterPtr writer;
};

namespace lttng {
namespace config {

/*
 * Return the domain type which the configuration string `text` (for example
 * `KERNEL` or `UST`) names, or `nonstd::nullopt` if `text` doesn't name a
 * domain type.
 */
nonstd::optional<lttng_domain_type> domain_type_from_string(const char *text) noexcept;

} /* namespace config */
} /* namespace lttng */

#endif /* LTTNG_CONFIG_CONFIG_INTERNAL_HPP */
