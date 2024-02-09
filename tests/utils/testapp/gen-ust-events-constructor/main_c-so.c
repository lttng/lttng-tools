/*
 * Copyright (C) 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-LIcense-Identifier: LGPL-2.1-only
 */

#include "tp-so_c.h"
#include "tp.h"

/* Use tracepoints defined and provided by shared libraries. */
void test_constructor_so(void) __attribute__((constructor));
void test_constructor_so(void)
{
	tracepoint(tp_so_c, constructor_c_provider_shared_library);
}

void test_destructor_so(void) __attribute__((destructor));
void test_destructor_so(void)
{
	tracepoint(tp_so_c, destructor_c_provider_shared_library);
}

int main(void)
{
	tracepoint(tp, main);
	return 0;
}
