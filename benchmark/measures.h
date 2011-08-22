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

/* Session daemon thread manage client time */
cycles_t time_sessiond_th_cli_start;
cycles_t time_sessiond_th_cli_poll;

#endif /* _MEASURES_H */
