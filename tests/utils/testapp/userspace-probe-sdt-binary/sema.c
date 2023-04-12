/*
 * Copyright (C) 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#include "foobar_provider.h"

#include <sys/sdt.h>
void sema_function()
{
	FOOBAR_TP_WITH_SEMAPHORE();
}
