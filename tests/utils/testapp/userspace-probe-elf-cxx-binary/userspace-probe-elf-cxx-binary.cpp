/*
 * Copyright (C) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#include "test_class.h"

volatile int not_a_function = 0;

void test_cxx_function() __attribute__ ((noinline));
void test_cxx_function()
{
	not_a_function += 1;
}

int main(int argc, char *argv[])
{
	test_class my_test_class;
	/* Call test function. */
	test_cxx_function();

	/* Call test method. */
	my_test_class.test_method();
	return 0;
}
