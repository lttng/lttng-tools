/*
 * SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "tp-a_c.h"
#include "tp.h"

/* Use tracepoints defined and provided by static archive. */
void test_constructor_a(void) __attribute__((constructor));
void test_constructor_a(void)
{
	tracepoint(tp_a_c, constructor_c_provider_static_archive);
}

void test_destructor_a(void) __attribute__((destructor));
void test_destructor_a(void)
{
	tracepoint(tp_a_c, destructor_c_provider_static_archive);
}

int main(void)
{
	tracepoint(tp, main);
	return 0;
}
