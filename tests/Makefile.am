AM_CFLAGS=-I$(top_srcdir)/include -I$(top_srcdir)/libkernelctl \
		  -I$(top_srcdir)/liblttngctl -g -Wall

noinst_PROGRAMS = test_sessions test_kernel_data_trace

SESSIONS=$(top_srcdir)/ltt-sessiond/session.c
KERN_DATA_TRACE=$(top_srcdir)/ltt-sessiond/trace.c

test_sessions_SOURCES = test_sessions.c $(SESSIONS)

test_kernel_data_trace_SOURCES = test_kernel_data_trace.c $(KERN_DATA_TRACE)

check-am:
	./runall.sh
