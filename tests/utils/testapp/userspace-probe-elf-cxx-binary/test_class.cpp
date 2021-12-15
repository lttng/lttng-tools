/*
 * Copyright (C) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#include "test_class.hpp"
test_class::test_class() {
	test_member = 1;
}

void test_class::test_method() {
	test_member += 1;
}
