/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
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

#ifndef _MEASURES_H
#define _MEASURES_H

/* Session daemon main() time */
cycles_t time_sessiond_boot_start;
cycles_t time_sessiond_boot_end;

/* Session daemon thread manage kconsumerd time */
cycles_t time_sessiond_th_kcon_start;
cycles_t time_sessiond_th_kcon_poll;

/* Session daemon thread manage kernel time */
cycles_t time_sessiond_th_kern_start;
cycles_t time_sessiond_th_kern_poll;

/* Session daemon thread manage apps time */
cycles_t time_sessiond_th_apps_start;
cycles_t time_sessiond_th_apps_poll;

/* Session daemon thread registration apps time */
cycles_t time_sessiond_th_reg_start;
cycles_t time_sessiond_th_reg_poll;

/* Session daemon thread registration apps time */
cycles_t time_sessiond_th_dispatch_start;
cycles_t time_sessiond_th_dispatch_block;

/* Session daemon thread manage client time */
cycles_t time_sessiond_th_cli_start;
cycles_t time_sessiond_th_cli_poll;

/* Create tracing session values */
cycles_t time_create_session_start;
cycles_t time_create_session_end;

/* Destroy tracing session values */
cycles_t time_destroy_session_start;
cycles_t time_destroy_session_end;

/*
 * UST registration time
 *
 * Start time is taken *after* the poll() has detected activity on the apps
 * socket and right *before* the accept(). There is a malloc() after that
 * accept and then we recv() the request from the client. We need to measure
 * the complete process.
 */
cycles_t time_ust_register_start;
/*
 * The stop time is measured right after the futex() wake up.
 */
cycles_t time_ust_register_stop;

/*
 *  * UST unregister time
 *   */
cycles_t time_ust_unregister_start;
cycles_t time_ust_unregister_stop;

/*
 * UST dispatch registration request time
 *
 * Start time taken *after* the dequeue which is a blocking call.
 */
cycles_t time_ust_dispatch_register_start;
/*
 * Stop time taken *before* the futex() wait so at this point, the registration
 * was sent to the manage apps thread.
 */
cycles_t time_ust_dispatch_register_stop;

/*
 * UST managing registration time
 */
/* read() from pipe */
cycles_t time_ust_register_read_start;
cycles_t time_ust_register_read_stop;
/* register_traceable_app() time */
cycles_t time_ust_register_add_start;
cycles_t time_ust_register_add_stop;
/* send register done command */
cycles_t time_ust_register_done_start;
cycles_t time_ust_register_done_stop;

/*
 * UST notification time (using the shm/futex scheme). Those times were break
 * down in seperate time for each big action step.
 *
 * Start time taken *before* we create/get the SHM mmap.
 */
cycles_t time_ust_notify_apps_start;
/*
 * Stop time taken after waiting all processes (futex_wait_update()).
 */
cycles_t time_ust_notify_apps_stop;
/* mmap() call */
cycles_t time_ust_notify_mmap_start;
cycles_t time_ust_notify_mmap_stop;
/* Permissions time (chmod/chown) */
cycles_t time_ust_notify_perms_start;
cycles_t time_ust_notify_perms_stop;
/* Fork process */
cycles_t time_ust_notify_fork_start;
cycles_t time_ust_notify_fork_stop;
/* shm_open call */
cycles_t time_ust_notify_shm_start;
cycles_t time_ust_notify_shm_stop;

#endif /* _MEASURES_H */
