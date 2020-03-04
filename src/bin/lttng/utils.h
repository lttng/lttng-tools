/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_UTILS_H
#define _LTTNG_UTILS_H

#include <popt.h>

#include <lttng/lttng.h>

extern char *opt_relayd_path;
extern int opt_no_sessiond;
extern char * opt_sessiond_path;
extern pid_t sessiond_pid;

struct cmd_struct;

char *get_session_name(void);
char *get_session_name_quiet(void);
void list_commands(struct cmd_struct *commands, FILE *ofp);
void list_cmd_options(FILE *ofp, struct poptOption *options);

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_u32(uint32_t x);

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_u64(uint64_t x);

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_ulong(unsigned long x);

const char *get_domain_str(enum lttng_domain_type domain);
const char *get_event_type_str(enum lttng_event_type event_type);

int print_missing_or_multiple_domains(unsigned int domain_count,
		bool include_agent_domains);

int spawn_relayd(const char *pathname, int port);
int check_relayd(void);
void print_session_stats(const char *session_name);
int show_cmd_help(const char *cmd_name, const char *help_msg);

int print_trace_archive_location(
		const struct lttng_trace_archive_location *location,
		const char *session_name);

#endif /* _LTTNG_UTILS_H */
