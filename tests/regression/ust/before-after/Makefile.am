AM_CFLAGS = -I$(srcdir) -O2
AM_LDFLAGS = -llttng-ust

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

noinst_PROGRAMS = gen-nevents
gen_nevents_SOURCES = gen-nevents.c tp.c ust_gen_nevents.h
gen_nevents_LDADD = -llttng-ust

noinst_SCRIPTS = test_before_after
EXTRA_DIST = test_before_after
