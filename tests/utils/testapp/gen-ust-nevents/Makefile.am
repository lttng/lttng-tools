AM_CPPFLAGS += -I$(srcdir) -I$(top_srcdir)/tests/utils

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-nevents
gen_ust_nevents_SOURCES = gen-ust-nevents.c tp.c tp.h
gen_ust_nevents_LDADD = -llttng-ust -lurcu-bp \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS)
endif
