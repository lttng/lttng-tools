/*
 * Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef _COMPAT_NETDB_H
#define _COMPAT_NETDB_H

#include <netdb.h>

#ifdef HAVE_GETHOSTBYNAME2
static inline struct hostent *lttng_gethostbyname2(const char *name, int af)
{
	return gethostbyname2(name, af);
}
#elif HAVE_GETIPNODEBYNAME
static inline struct hostent *lttng_gethostbyname2(const char *name, int af)
{
	int unused;

	return getipnodebyname(name, af, AI_DEFAULT, &unused);
}
#else
#error "Missing compat for gethostbyname2()"
#endif

#endif /* _COMPAT_NETDB_H */
