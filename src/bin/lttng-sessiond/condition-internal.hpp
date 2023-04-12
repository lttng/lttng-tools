/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_SESSIOND_CONDITION_INTERNAL_H
#define LTTNG_SESSIOND_CONDITION_INTERNAL_H

#include <lttng/condition/condition.h>

/*
 * The lttng_condition hashing code is kept in this file (rather than
 * condition.c) since it makes use of GPLv2 code (hashtable utils), which we
 * don't want to link in liblttng-ctl.
 */
unsigned long lttng_condition_hash(const struct lttng_condition *condition);

struct lttng_condition *lttng_condition_copy(const struct lttng_condition *condition);

#endif /* LTTNG_SESSIOND_CONDITION_INTERNAL_H */
