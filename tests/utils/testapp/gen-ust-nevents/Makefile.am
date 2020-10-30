# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir) -I$(top_srcdir)/tests/utils \
	-I$(top_srcdir)/tests/utils/testapp

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-nevents
gen_ust_nevents_SOURCES = gen-ust-nevents.c tp.c tp.h
gen_ust_nevents_LDADD = $(UST_LIBS) $(URCU_BP_LIBS) \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS)
endif
