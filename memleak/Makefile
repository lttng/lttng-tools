# Copyright (C) 2013  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
# OR IMPLIED. ANY USE IS AT YOUR OWN RISK.
#
# Permission is hereby granted to use or copy this program for any
# purpose, provided the above notices are retained on all copies.
# Permission to modify the code and to distribute modified code is
# granted, provided the above notices are retained, and a notice that
# the code was modified is included with the above copyright notice.

# This Makefile is not using automake so that users may see how to build
# a program with tracepoint provider probes as stand-alone shared objects.

CC = gcc
LDFLAGS=-ldl
CFLAGS=-g -Wall

all: lttng-memleak-finder.so lttng-malloc-stats.so

lttng-memleak-finder.o: lttng-memleak-finder.c jhash.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

lttng-memleak-finder.so: lttng-memleak-finder.o
	$(CC) -shared -o $@ $(LDFLAGS) $^

lttng-malloc-stats.o: lttng-malloc-stats.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

lttng-malloc-stats.so: lttng-malloc-stats.o
	$(CC) -shared -o $@ $(LDFLAGS) $^

.PHONY: clean
clean:
	rm -f *.o *.so
