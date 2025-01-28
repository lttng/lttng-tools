/*
 * SPDX-FileCopyrightText: 2015 Antoine Busque <abusque@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <unistd.h>

#define TRACEPOINT_DEFINE
#include "tp.h"

int main(void)
{
	sleep(1);
	return 0;
}
