/*
 * Copyright (C) 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

/*
 * The order of inclusion is important here: including sdt.h _after_ the probe
 * declarations ensures that semaphore-protected SDT probes are
 * generated. See SYSTEMTAP(2) for more details.
 */
/* clang-format off */
#include "foobar_provider.h"
#include <sys/sdt.h>
/* clang-format on */

void sema_function()
{
	FOOBAR_TP_WITH_SEMAPHORE();
}
