/*
 * Copyright (C) 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef LTTNG_EXPORT_H
#define LTTNG_EXPORT_H
#if defined(_WIN32) || defined(__CYGWIN__)
#define LTTNG_EXPORT
#else
#define LTTNG_EXPORT __attribute__((visibility("default")))
#endif
#endif
