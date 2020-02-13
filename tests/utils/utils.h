/*
 * Copyright (C) 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#if !defined(__GLIBC__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE))

/*
 * Version using XSI strerror_r.
 */
#define PERROR_NO_LOGGER(msg, args...)                      \
	do {                                                \
		char buf[200];                              \
		strerror_r(errno, buf, sizeof(buf));        \
		fprintf(stderr, msg ": %s\n", ##args, buf); \
	} while (0);
#else
/*
 * Version using GNU strerror_r, for linux with appropriate defines.
 */
#define PERROR_NO_LOGGER(msg, args...)                      \
	do {                                                \
		char *buf;                                  \
		char tmp[200];                              \
		buf = strerror_r(errno, tmp, sizeof(tmp));  \
		fprintf(stderr, msg ": %s\n", ##args, buf); \
	} while (0);
#endif

int usleep_safe(useconds_t usec);
int create_file(const char *path);
int wait_on_file(const char *path);

#endif /* TEST_UTILS_H */
