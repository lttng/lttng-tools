AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_LTLIBRARIES = liblttng-benchmark.la

liblttng_benchmark_la_SOURCES = benchmark.c benchmark.h cpu.c cpu.h

bench:
	./runall.sh
