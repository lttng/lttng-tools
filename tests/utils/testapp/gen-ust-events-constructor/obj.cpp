/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "obj.h"
#include "tp-a.h"
#include "tp-so.h"
#include "tp.h"

Obj::Obj(const char *_msg) : msg(_msg)
{
	tracepoint(tp, constructor_cplusplus, msg);
}

Obj::~Obj()
{
	tracepoint(tp, destructor_cplusplus, msg);
}

Objso::Objso(const char *_msg) : msg(_msg)
{
	tracepoint(tp_so, constructor_cplusplus_provider_shared_library, msg);
}

Objso::~Objso()
{
	tracepoint(tp_so, destructor_cplusplus_provider_shared_library, msg);
}

Obja::Obja(const char *_msg) : msg(_msg)
{
	tracepoint(tp_a, constructor_cplusplus_provider_static_archive, msg);
}

Obja::~Obja()
{
	tracepoint(tp_a, destructor_cplusplus_provider_static_archive, msg);
}
