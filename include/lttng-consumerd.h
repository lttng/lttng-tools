/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only verion 2
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

#ifndef _LTTNG_CONSUMERD_H
#define _LTTNG_CONSUMERD_H

/* Kernel consumer path */
#define KCONSUMERD_PATH                     LTTNG_RUNDIR "/kconsumerd"
#define KCONSUMERD_CMD_SOCK_PATH            KCONSUMERD_PATH "/command"
#define KCONSUMERD_ERR_SOCK_PATH            KCONSUMERD_PATH "/error"

/* UST 64-bit consumer path */
#define USTCONSUMERD64_PATH                 LTTNG_RUNDIR "/ustconsumerd64"
#define USTCONSUMERD64_CMD_SOCK_PATH        USTCONSUMERD64_PATH "/command"
#define USTCONSUMERD64_ERR_SOCK_PATH        USTCONSUMERD64_PATH "/error"

/* UST 32-bit consumer path */
#define USTCONSUMERD32_PATH                 LTTNG_RUNDIR "/ustconsumerd32"
#define USTCONSUMERD32_CMD_SOCK_PATH        USTCONSUMERD32_PATH "/command"
#define USTCONSUMERD32_ERR_SOCK_PATH        USTCONSUMERD32_PATH "/error"

#endif /* _LTTNG_CONSUMERD_H */
