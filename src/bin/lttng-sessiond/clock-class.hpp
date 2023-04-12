/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CLOCK_CLASS_H
#define LTTNG_CLOCK_CLASS_H

#include <common/compat/time.hpp>
#include <common/uuid.hpp>

#include <vendor/optional.hpp>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/time.h>
#include <urcu/arch.h>
#include <urcu/system.h>

namespace lttng {
namespace sessiond {
namespace trace {

class trace_class_visitor;

class clock_class {
public:
	using cycles_t = uint64_t;
	using scycles_t = int64_t;
	using cuptr = std::unique_ptr<const clock_class>;

	virtual ~clock_class() = default;
	clock_class(const clock_class&) = delete;
	clock_class(clock_class&&) = delete;
	clock_class& operator=(clock_class&&) = delete;
	clock_class& operator=(const clock_class&) = delete;

	virtual void accept(trace_class_visitor& visitor) const;

	const std::string name;
	const std::string description;
	const nonstd::optional<lttng_uuid> uuid;
	const scycles_t offset;
	const cycles_t frequency;

protected:
	clock_class(std::string name,
		    std::string description,
		    nonstd::optional<lttng_uuid> uuid,
		    scycles_t offset,
		    cycles_t frequency);
};

} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_CLOCK_CLASS_H */
