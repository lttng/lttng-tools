# SPDX-License-Identifier: GPL-2.0-only

noinst_LTLIBRARIES = libhashtable.la

libhashtable_la_SOURCES = hashtable.c hashtable.h \
                         utils.c utils.h \
                         hashtable-symbols.h

libhashtable_la_LIBADD = $(URCU_LIBS) $(URCU_CDS_LIBS)
