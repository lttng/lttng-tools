AM_CPPFLAGS += -I$(srcdir)
AM_LDFLAGS =

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-tracef
gen_ust_tracef_SOURCES = gen-ust-tracef.c
gen_ust_tracef_LDADD = -llttng-ust
endif
