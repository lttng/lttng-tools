/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTTNG_UTILS_H
#define _LTTNG_UTILS_H

#include <popt.h>
#include "version.h"

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

int print_missing_or_multiple_domains(unsigned int sum);

int spawn_relayd(const char *pathname, int port);
int check_relayd(void);
void print_session_stats(const char *session_name);
int show_cmd_help(const char *cmd_name, const char *help_msg);

#endif /* _LTTNG_UTILS_H */
