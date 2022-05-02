/*
 * Copyright (C) 2010 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _UST_CLOCK_H
#define _UST_CLOCK_H

#include <common/compat/time.hpp>
#include <common/uuid.hpp>
#include <vendor/optional.hpp>

#include <lttng/ust-clock.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/time.h>
#include <urcu/arch.h>
#include <urcu/system.h>

namespace lttng {
namespace ust {

class clock_attributes_sample {
public:
	using cycles_t = uint64_t;
	using scycles_t = int64_t;

	clock_attributes_sample();

	const std::string _name;
	const std::string _description;
	const nonstd::optional<lttng_uuid> _uuid;
	const scycles_t _offset;
	const cycles_t _frequency;
};

} /* namespace ust */
} /* namespace lttng */

#endif /* _UST_CLOCK_H */
