# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir) -I$(top_srcdir)/tests/utils \
	-I$(top_srcdir)/tests/utils/testapp

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-nevents-str
gen_ust_nevents_str_SOURCES = gen-ust-nevents-str.c tp.c tp.h
gen_ust_nevents_str_LDADD = $(UST_LIBS) \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS)
endif
