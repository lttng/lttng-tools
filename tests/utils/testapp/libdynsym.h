/*
 * SPDX-FileCopyrightText: 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#include <lttng/lttng-export.h>

LTTNG_EXPORT __attribute__((no_profile_instrument_function)) int dynamic_symbol(int a);
