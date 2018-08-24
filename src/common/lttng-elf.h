#ifndef _LTTNG_ELF_H
#define _LTTNG_ELF_H
/*
 * Copyright (C) 2017  Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright (C) 2017  Erica Bugden <erica.bugden@efficios.com>
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

int lttng_elf_get_symbol_offset(int fd, char *symbol, uint64_t *offset);

int lttng_elf_get_sdt_probe_offsets(int fd, const char *provider_name,
		const char *probe_name, uint64_t **offsets, uint32_t *nb_probe);

#endif	/* _LTTNG_ELF_H */
