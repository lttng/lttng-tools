# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir) \
	-I$(top_srcdir)/tests/utils/testapp

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-tracef
gen_ust_tracef_SOURCES = gen-ust-tracef.cpp
gen_ust_tracef_LDADD = $(UST_LIBS) $(DL_LIBS)
endif
