/*
 * Copyright (C) 2013 Christian Babeux <christian.babeux@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */


#include <signal.h>

int main(int argc, char *argv[])
{
	raise(SIGSEGV);
	return 0;
}
