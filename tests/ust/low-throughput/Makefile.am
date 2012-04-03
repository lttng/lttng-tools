AM_CFLAGS = -I. -O2
AM_LDFLAGS = -llttng-ust

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

noinst_PROGRAMS = gen-events
gen_events_SOURCES = main.c tp.c tp.h
gen_events_LDADD = -llttng-ust -lurcu

noinst_SCRIPTS = run
EXTRA_DIST = run
