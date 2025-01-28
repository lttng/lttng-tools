/*
 * SPDX-FileCopyrightText: 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#include "foo.h"

int dynamic_symbol(int a)
{
	return a + a;
}
