/*
 * SPDX-FileCopyrightText: 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <lttng/lttng.h>

#include <assert.h>

int main(int argc, const char **argv)
{
	assert(argc >= 2);
	lttng_data_pending(argv[1]);
	return 0;
}
