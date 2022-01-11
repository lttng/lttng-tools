# SPDX-License-Identifier: GPL-2.0-only

noinst_LTLIBRARIES = libhashtable-gpl.la libhashtable-lgpl.la

libhashtable_lgpl_la_SOURCES = \
	seed.cpp \
	utils.cpp \
	utils.h

libhashtable_gpl_la_SOURCES = \
	hashtable.cpp \
	hashtable.h \
	hashtable-symbols.h

libhashtable_gpl_la_LIBADD = \
	$(URCU_LIBS) \
	$(URCU_CDS_LIBS)
