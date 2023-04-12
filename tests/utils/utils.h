/*
 * Copyright (C) 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <unistd.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(__GLIBC__) || \
	((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE))

/*
 * Version using XSI strerror_r.
 */
#define PERROR_NO_LOGGER(msg, args...)                               \
	do {                                                         \
		char _perror_buf[200];                               \
		strerror_r(errno, _perror_buf, sizeof(_perror_buf)); \
		fprintf(stderr, msg ": %s\n", ##args, _perror_buf);  \
	} while (0);
#else
/*
 * Version using GNU strerror_r, for linux with appropriate defines.
 */
#define PERROR_NO_LOGGER(msg, args...)                                             \
	do {                                                                       \
		char *_perror_buf;                                                 \
		char _perror_tmp[200];                                             \
		_perror_buf = strerror_r(errno, _perror_tmp, sizeof(_perror_tmp)); \
		fprintf(stderr, msg ": %s\n", ##args, _perror_buf);                \
	} while (0);
#endif

int usleep_safe(useconds_t usec);
int create_file(const char *path);
int wait_on_file(const char *path);

#if defined(__cplusplus)
}
#endif

#endif /* TEST_UTILS_H */
