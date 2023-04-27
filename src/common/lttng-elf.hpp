#ifndef _LTTNG_ELF_H
#define _LTTNG_ELF_H
/*
 * Copyright (C) 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright (C) 2017 Erica Bugden <erica.bugden@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#include <lttng/lttng-export.h>

#include <stdint.h>

extern "C" LTTNG_EXPORT int lttng_elf_get_symbol_offset(int fd, char *symbol, uint64_t *offset);

extern "C" LTTNG_EXPORT int lttng_elf_get_sdt_probe_offsets(int fd,
							    const char *provider_name,
							    const char *probe_name,
							    uint64_t **offsets,
							    uint32_t *nb_probe);

#endif /* _LTTNG_ELF_H */
