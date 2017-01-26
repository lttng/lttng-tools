/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _COMPAT_ENDIAN_H
#define _COMPAT_ENDIAN_H

#if defined(__linux__) || defined(__CYGWIN__)
#include <endian.h>

/*
 * htobe/betoh are not defined for glibc <2.9, so add them
 * explicitly if they are missing.
 */
#ifdef __USE_BSD
/* Conversion interfaces. */
# include <byteswap.h>

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  ifndef htobe16
#   define htobe16(x) __bswap_16(x)
#  endif
#  ifndef htole16
#   define htole16(x) (x)
#  endif
#  ifndef be16toh
#   define be16toh(x) __bswap_16(x)
#  endif
#  ifndef le16toh
#   define le16toh(x) (x)
#  endif

#  ifndef htobe32
#   define htobe32(x) __bswap_32(x)
#  endif
#  ifndef htole32
#   define htole32(x) (x)
#  endif
#  ifndef be32toh
#   define be32toh(x) __bswap_32(x)
#  endif
#  ifndef le32toh
#   define le32toh(x) (x)
#  endif

#  ifndef htobe64
#   define htobe64(x) __bswap_64(x)
#  endif
#  ifndef htole64
#   define htole64(x) (x)
#  endif
#  ifndef be64toh
#   define be64toh(x) __bswap_64(x)
#  endif
#  ifndef le64toh
#   define le64toh(x) (x)
#  endif

# else /* __BYTE_ORDER == __LITTLE_ENDIAN */
#  ifndef htobe16
#   define htobe16(x) (x)
#  endif
#  ifndef htole16
#   define htole16(x) __bswap_16(x)
#  endif
#  ifndef be16toh
#   define be16toh(x) (x)
#  endif
#  ifndef le16toh
#   define le16toh(x) __bswap_16(x)
#  endif

#  ifndef htobe32
#   define htobe32(x) (x)
#  endif
#  ifndef htole32
#   define htole32(x) __bswap_32(x)
#  endif
#  ifndef be32toh
#   define be32toh(x) (x)
#  endif
#  ifndef le32toh
#   define le32toh(x) __bswap_32(x)
#  endif

#  ifndef htobe64
#   define htobe64(x) (x)
#  endif
#  ifndef htole64
#   define htole64(x) __bswap_64(x)
#  endif
#  ifndef be64toh
#   define be64toh(x) (x)
#  endif
#  ifndef le64toh
#   define le64toh(x) __bswap_64(x)
#  endif

# endif /* __BYTE_ORDER == __LITTLE_ENDIAN */
#endif /* __USE_BSD */

#elif defined(__FreeBSD__)
#include <machine/endian.h>

#elif defined(__sun__)
#include <sys/byteorder.h>
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif /* __BIG_ENDIAN */
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif /* __LITTLE_ENDIAN */

#ifdef _LITTLE_ENDIAN
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif /* _LITTLE_ENDIAN */
#ifdef _BIG_ENDIAN
#define __BYTE_ORDER __BIG_ENDIAN
#endif /* _BIG_ENDIAN */

#define LITTLE_ENDIAN  __LITTLE_ENDIAN
#define BIG_ENDIAN     __BIG_ENDIAN
#define PDP_ENDIAN     __PDP_ENDIAN
#define BYTE_ORDER     __BYTE_ORDER

#define betoh16(x) BE_16(x)
#define letoh16(x) LE_16(x)
#define betoh32(x) BE_32(x)
#define letoh32(x) LE_32(x)
#define betoh64(x) BE_64(x)
#define letoh64(x) LE_64(x)
#define htobe16(x) BE_16(x)
#define be16toh(x) BE_16(x)
#define htobe32(x) BE_32(x)
#define be32toh(x) BE_32(x)
#define htobe64(x) BE_64(x)
#define be64toh(x) BE_64(x)

#elif defined(__APPLE__)
# include <machine/endian.h>
# include <libkern/OSByteOrder.h>

# if BYTE_ORDER == LITTLE_ENDIAN
#  define htobe16(x) OSSwapConstInt16(x)
#  define htole16(x) (x)
#  define be16toh(x) OSSwapConstInt16(x)
#  define le16toh(x) (x)

#  define htobe32(x) OSSwapConstInt32(x)
#  define htole32(x) (x)
#  define be32toh(x) OSSwapConstInt32(x)
#  define le32toh(x) (x)

#  define htobe64(x) OSSwapConstInt64(x)
#  define htole64(x) (x)
#  define be64toh(x) OSSwapConstInt64(x)
#  define le64toh(x) (x)

# else /* BYTE_ORDER == LITTLE_ENDIAN */
#  define htobe16(x) (x)
#  define htole16(x) OSSwapConstInt16(x)
#  define be16toh(x) (x)
#  define le16toh(x) OSSwapConstInt16(x)

#  define htobe32(x) (x)
#  define htole32(x) OSSwapConstInt32(x)
#  define be32toh(x) (x)
#  define le32toh(x) OSSwapConstInt32(x)

#  define htobe64(x) (x)
#  define htole64(x) OSSwapConstInt64(x)
#  define be64toh(x) (x)
#  define le64toh(x) OSSwapConstInt64(x)
# endif

#else
#error "Please add support for your OS."
#endif

#endif /* _COMPAT_ENDIAN_H */
