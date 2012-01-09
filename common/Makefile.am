AM_CPPFLAGS = -I$(top_srcdir)/include

AM_CFLAGS = -fno-strict-aliasing

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = hashtable.c hashtable.h \
                       hashtable/rculfhash.c \
                       hashtable/rculfhash.h \
                       hashtable/hash.c hashtable/hash.h \
		       runas.c
