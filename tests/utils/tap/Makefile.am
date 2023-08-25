# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/src/ -I$(top_srcdir)/include

noinst_PROGRAMS = clock
clock_SOURCES = clock.cpp
clock_CPPFLAGS = $(AM_CPPFLAGS)
noinst_LTLIBRARIES = libtap.la
libtap_la_SOURCES = tap.c tap.h
libtap_la_LIBADD = ../libtestutils.la
dist_noinst_SCRIPTS = tap.sh
EXTRA_DIST = tap.sh

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
