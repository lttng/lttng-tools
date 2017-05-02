AM_CPPFLAGS += -I$(srcdir) -I$(top_srcdir)/tests/utils

if LTTNG_TOOLS_BUILD_WITH_LIBDL
LIBS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
LIBS += -lc
endif

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-nevents-str
gen_ust_nevents_str_SOURCES = gen-ust-nevents-str.c tp.c tp.h
gen_ust_nevents_str_LDADD = -llttng-ust -lurcu-bp \
		$(top_builddir)/tests/utils/libtestutils.la
endif
