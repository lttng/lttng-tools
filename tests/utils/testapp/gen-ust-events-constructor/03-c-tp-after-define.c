/*
 * Copyright (C) 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "tp.h"

void test_constructor3(void) __attribute__((constructor));
void test_constructor3(void)
{
	tracepoint(tp, constructor_c_across_units_after_define);
}

void test_destructor3(void) __attribute__((destructor));
void test_destructor3(void)
{
	tracepoint(tp, destructor_c_across_units_after_define);
}
