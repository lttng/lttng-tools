AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

noinst_LTLIBRARIES = libhashtable.la

libhashtable_la_SOURCES = hashtable.c hashtable.h \
                         utils.c utils.h \
                         hashtable-symbols.h

libhashtable_la_LIBADD = -lurcu-common -lurcu -lurcu-cds
