/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_UTILS_H
#define _LTT_UTILS_H

struct lttng_ht;
struct consumer_output;

const char *get_home_dir();
int notify_thread_pipe(int wpipe);
int loglevels_match(int a_loglevel_type,
		    int a_loglevel_value,
		    int b_loglevel_type,
		    int b_loglevel_value,
		    int loglevel_all_type);
const char *consumer_output_get_base_path(const struct consumer_output *output);
bool force_experimental_ctf_2();

#endif /* _LTT_UTILS_H */
