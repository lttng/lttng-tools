/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef _OBJ_H
#define _OBJ_H

struct Obj {
	const char *msg;
	explicit Obj(const char *msg);
	~Obj();
};

struct Objso {
	const char *msg;
	explicit Objso(const char *msg);
	~Objso();
};

#endif /* _OBJ_H */
