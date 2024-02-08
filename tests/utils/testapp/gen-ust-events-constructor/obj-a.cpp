/*
 * Copyright (C) 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifer: LGPL-2.1-only
 */

#include "obj-a.h"
#include "tp-a.h"
#include "tp.h"

Obj::Obj(const char *_msg) : msg(_msg)
{
	tracepoint(tp, constructor_cplusplus, msg);
}

Obj::~Obj()
{
	tracepoint(tp, destructor_cplusplus, msg);
}

Obja::Obja(const char *_msg) : msg(_msg)
{
	tracepoint(tp_a, constructor_cplusplus_provider_static_archive, msg);
}

Obja::~Obja()
{
	tracepoint(tp_a, destructor_cplusplus_provider_static_archive, msg);
}
