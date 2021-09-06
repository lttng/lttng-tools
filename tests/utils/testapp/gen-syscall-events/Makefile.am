# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = gen-syscall-events
gen_syscall_events_SOURCES = gen-syscall-events.cpp
gen_syscall_events_LDADD = $(top_builddir)/tests/utils/libtestutils.la
