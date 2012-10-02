AM_CFLAGS = -I$(srcdir) -O2
AM_LDFLAGS = -llttng-ust

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

noinst_PROGRAMS = gen-events-time
gen_events_time_SOURCES = gen-events-time.c tp.c ust_gen_event.h
gen_events_time_LDADD = -llttng-ust

noinst_SCRIPTS = run
EXTRA_DIST = run
