/*
 * Copyright (C) 2013 Christian Babeux <christian.babeux@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <signal.h>

int main(void)
{
	raise(SIGSEGV);
	return 0;
}
