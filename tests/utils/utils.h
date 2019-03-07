/*
 * Copyright (C) 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

int usleep_safe(useconds_t usec);
int create_file(const char *path);
int wait_on_file(const char *path);

#endif /* TEST_UTILS_H */
