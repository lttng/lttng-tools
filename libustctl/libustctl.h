/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 *               2011  David Goulet <david.goulet@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _LTT_LIBUSTCTL_H
#define _LTT_LIBUSTCTL_H

#define USTCTL_ERR_CONN		1 /* Process connection error */
#define USTCTL_ERR_ARG		2 /* Invalid function argument */
#define USTCTL_ERR_GEN		3 /* General ustctl error */

#define USTCTL_MS_CHR_OFF	'0' /* Marker state 'on' character */
#define USTCTL_MS_CHR_ON	'1' /* Marker state 'on' character */
#define USTCTL_MS_OFF		0   /* Marker state 'on' value */
#define USTCTL_MS_ON		1   /* Marker state 'on' value */

/*
 * Channel/marker/state/format string (cmsf) data structure
 */
struct ustctl_marker_status {
	char *channel;         /* Channel name (end of ustctl_marker_status array if NULL) */
	char *ust_marker;      /* Marker name (end of ustctl_marker_status array if NULL) */
	int state;             /* State (0 := marker disabled, 1 := marker enabled) */
	char *fs;              /* Format string (end of ustctl_marker_status array if NULL) */
};

struct ustctl_trace_event_status {
	char *name;
};

pid_t *ustctl_get_online_pids(void);

int ustctl_alloc_trace(int sock, const char *trace);
int ustctl_connect_pid(pid_t pid);
int ustctl_create_trace(int sock, const char *trace);
int ustctl_destroy_trace(int sock, const char *trace);
int ustctl_force_switch(int sock, const char *trace);
int ustctl_free_cmsf(struct ustctl_marker_status *cmsf);
int ustctl_free_tes(struct ustctl_trace_event_status *tes);
int ustctl_get_cmsf(int sock, struct ustctl_marker_status **cmsf);
int ustctl_get_sock_path(int sock, char **sock_path);
int ustctl_get_subbuf_num(pid_t pid, const char *trace, const char *channel);
int ustctl_get_subbuf_size(int sock, const char *trace, const char *channel);
int ustctl_get_tes(int sock, struct ustctl_trace_event_status **tes);
int ustctl_set_sock_path(int sock, const char *sock_path);

int ustctl_set_marker_state(int sock, const char *trace,
		const char *channel, const char *ust_marker, int state);

int ustctl_set_subbuf_size(int sock, const char *trace,
		const char *channel, unsigned int subbuf_size);

int ustctl_set_subbuf_num(int sock, const char *trace,
		const char *channel, unsigned int num);

int ustctl_setup_and_start(int sock, const char *trace);
int ustctl_start_trace(int sock, const char *trace);
int ustctl_stop_trace(int sock, const char *trace);
unsigned int ustctl_count_nl(const char *str);

#endif /* _LTT_LIBUSTCTL_H */
