AM_CFLAGS=-I$(top_srcdir)/include -I$(top_srcdir)/libkernelctl \
		  -I$(top_srcdir)/liblttngctl -g -Wall

noinst_PROGRAMS = test_sessions

SESSIONS=$(top_srcdir)/ltt-sessiond/session.c

test_sessions_SOURCES = test_sessions.c $(SESSIONS)

check-am:
	./runall.sh
