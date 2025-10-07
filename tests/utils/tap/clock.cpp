/*
 * SPDX-FileCopyrightText: 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "common/time.hpp"
#include "common/format.hpp"

int main()
{
	struct timespec t;
	const auto ret = lttng_clock_gettime(CLOCK_MONOTONIC, &t);

	if (ret == 0) {
		fmt::print("{}.{:09d}\n", t.tv_sec, t.tv_nsec);
	}

	return ret;
}
