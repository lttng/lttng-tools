/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_LIST_MI_HPP
#define _LTTNG_LIST_MI_HPP

/*
 * Machine interface output for the list command.
 *
 * Returns CMD_SUCCESS on success, appropriate error code otherwise.
 */
int list_mi(const char *session_name,
	    int opt_kernel,
	    int opt_userspace,
	    int opt_jul,
	    int opt_log4j,
	    int opt_log4j2,
	    int opt_python,
	    const char *opt_channel,
	    int opt_domain,
	    int opt_fields,
	    int opt_syscall);

#endif /* _LTTNG_LIST_MI_HPP */
