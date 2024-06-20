/*
 * Copyright (C) 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _OBJ_A_H
#define _OBJ_A_H

struct Obj {
	const char *msg;
	explicit Obj(const char *msg);
	~Obj();
};

struct Obja {
	const char *msg;
	explicit Obja(const char *msg);
	~Obja();
};

#endif /* _OBJ_A_H */
