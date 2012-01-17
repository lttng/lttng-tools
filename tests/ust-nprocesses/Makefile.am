AM_CPPFLAGS = -ldl -I. -O2

noinst_PROGRAMS = gen-events-time
gen_events_time_SOURCES = gen-events-time.c tp.c ust_gen_event.h
gen_events_time_LDADD = -llttng-ust

noinst_SCRIPTS = run
EXTRA_DIST = run
