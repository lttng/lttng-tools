/*
 * SPDX-FileCopyrightText: 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

class test_class {
public:
	test_class();
	__attribute__((no_profile_instrument_function)) void test_method();
	volatile int test_member;
};
