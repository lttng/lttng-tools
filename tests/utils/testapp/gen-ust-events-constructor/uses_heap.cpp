/*
 * SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <lttng/ust-compiler.h>

int main()
{
#ifdef LTTNG_UST_ALLOCATE_COMPOUND_LITERAL_ON_HEAP
	return 0;
#else
	return 1;
#endif
}
