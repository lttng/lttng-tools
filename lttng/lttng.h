/* Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTTNG_H
#define _LTTNG_H

/* Function prototypes */
int parse_args(int argc, const char **argv);
void clean_exit(int code);

/* Command line options */
extern int opt_trace_kernel;
extern int opt_verbose;
extern int opt_quiet;
extern char *opt_tracing_group;
extern char *opt_session_uuid;
extern char *opt_create_session;
extern char *opt_sessiond_path;
extern char *opt_destroy_session;
extern int opt_list_apps;
extern int opt_no_sessiond;
extern int opt_list_session;
extern int opt_list_traces;
extern pid_t opt_create_trace;
extern pid_t opt_start_trace;
extern pid_t opt_stop_trace;

#endif /* _LTTNG_H */
