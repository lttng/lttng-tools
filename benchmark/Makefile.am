AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

noinst_LTLIBRARIES = liblttng-benchmark.la

noinst_PROGRAMS = bench_sessions

UTILS=utils.h
SESSIONS=$(top_srcdir)/src/bin/lttng-sessiond/session.c

liblttng_benchmark_la_SOURCES = benchmark.c benchmark.h cpu.c cpu.h

bench_sessions_SOURCES = bench-sessions.c $(SESSIONS) $(UTILS)
bench_sessions_LDADD = $(top_builddir)/benchmark/liblttng-benchmark.la \
					   $(top_builddir)/src/common/libcommon.la

bench:
	./runall.sh
