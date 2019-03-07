/*
 * Copyright (C) 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#include "foo.h"
volatile int not_a_function = 0;

void __attribute__ ((noinline)) test_function();
void __attribute__ ((noinline)) test_function()
{
	not_a_function += 1;
}

int main(int argc, char *argv[])
{
	test_function();
	dynamic_symbol(42);
	return 0;
}
