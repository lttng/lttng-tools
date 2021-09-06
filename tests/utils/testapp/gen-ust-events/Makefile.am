# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(srcdir) \
	-I$(top_srcdir)/tests/utils/testapp

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-events
gen_ust_events_SOURCES = \
	gen-ust-events.cpp \
	tp.c \
	tp.h
gen_ust_events_LDADD = $(UST_LIBS) \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS)
endif
