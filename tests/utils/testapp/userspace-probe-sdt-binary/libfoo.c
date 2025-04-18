/*
 * SPDX-FileCopyrightText: 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

/*
 * The order of inclusion is important here: including sdt.h _before_ the probe
 * declarations ensures that semaphore-protected SDT probes (which we don't support) are not
 * generated. See SYSTEMTAP(2) for more details.
 */
/* clang-format off */
#include <sys/sdt.h>
#include "foobar_provider.h"
/* clang-format on */

void foo_function()
{
	FOOBAR_TP_IN_SHARED_OBJECT();
}
void overridable_function()
{
}
