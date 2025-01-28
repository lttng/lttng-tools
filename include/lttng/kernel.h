/*
 * kernel.h
 *
 * Linux Trace Toolkit Control Library Header File
 *
 * SPDX-FileCopyrightText: 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_KERNEL_H
#define LTTNG_KERNEL_H

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_kernel_tracer_status {
	/* Loaded without error. */
	LTTNG_KERNEL_TRACER_STATUS_INITIALIZED = 0,
	/* Unknown error. */
	LTTNG_KERNEL_TRACER_STATUS_ERR_UNKNOWN = -1,
	/* lttng-sessiond isn't running as root. */
	LTTNG_KERNEL_TRACER_STATUS_ERR_NEED_ROOT = -2,
	/* Notifier setup failed. */
	LTTNG_KERNEL_TRACER_STATUS_ERR_NOTIFIER = -3,
	/* Failed to open /proc/lttng. */
	LTTNG_KERNEL_TRACER_STATUS_ERR_OPEN_PROC_LTTNG = -4,
	/* Version mismatch between kernel tracer and kernel tracer ABI. */
	LTTNG_KERNEL_TRACER_STATUS_ERR_VERSION_MISMATCH = -5,
	/* Kernel module loading failed. */
	LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_UNKNOWN = -6,
	/* Kernel modules missing. */
	LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_MISSING = -7,
	/* Kernel module signature error. */
	LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_SIGNATURE = -8,
};

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_KERNEL_H */
