/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_FUTEX_H
#define _LTT_FUTEX_H

#ifdef __cplusplus
extern "C" {
#endif

void futex_wait_update(int32_t *futex, int active);
void futex_nto1_prepare(int32_t *futex);
void futex_nto1_wait(int32_t *futex);
void futex_nto1_wake(int32_t *futex);

#ifdef __cplusplus
}
#endif

#endif /* _LTT_FUTEX_H */
