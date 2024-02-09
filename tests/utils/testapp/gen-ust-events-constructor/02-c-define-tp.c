/*
 * Copyright (C) 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

static void fct_constructor2(void);
static void fct_destructor2(void);

void test_constructor2_same_unit_before(void) __attribute__((constructor));
void test_constructor2_same_unit_before(void)
{
	fct_constructor2();
}

void test_destructor2_same_unit_before(void) __attribute__((destructor));
void test_destructor2_same_unit_before(void)
{
	fct_destructor2();
}

#define TRACEPOINT_DEFINE
#include "tp.h"

static void fct_constructor2(void)
{
	tracepoint(tp, constructor_c_same_unit_before_define);
}

static void fct_destructor2(void)
{
	tracepoint(tp, destructor_c_same_unit_before_define);
}

void test_constructor2_same_unit_after(void) __attribute__((constructor));
void test_constructor2_same_unit_after(void)
{
	tracepoint(tp, constructor_c_same_unit_after_define);
}

void test_destructor2_same_unit_after(void) __attribute__((destructor));
void test_destructor2_same_unit_after(void)
{
	tracepoint(tp, destructor_c_same_unit_after_define);
}
