# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(srcdir) \
	-I$(top_srcdir)/tests/utils/testapp

if HAVE_LIBLTTNG_UST_CTL
# Disable some warnings flags to accomodate the tracepoint headers
WARN_FLAGS = \
	-Wno-redundant-decls \
	-Wno-missing-field-initializers

AM_CFLAGS += $(WARN_FLAGS)
AM_CXXFLAGS += $(WARN_FLAGS)

if NO_SHARED
# Build the shared library as a static archive if shared libraries
# are disabled.
FORCE_SHARED_LIB_OPTIONS =
else
# Force the shared flag on the noinst libraries since they are
# only built static by default
FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
			   -rpath $(abs_builddir)
endif

noinst_LTLIBRARIES = libtp-so-provider.la libtp-so-define.la \
		     libtp-so_c-provider.la libtp-so_c-define.la \
		     libtp-a-provider.la libtp-a-define.la \
		     libtp-a_c-provider.la libtp-a_c-define.la

# dynamic libraries
libtp_so_provider_la_SOURCES = \
	tp-so-provider.cpp \
	tp-so.h
libtp_so_provider_la_LDFLAGS = \
	$(FORCE_SHARED_LIB_OPTIONS)

libtp_so_define_la_SOURCES = \
	tp-so-define.cpp \
	tp-so.h
libtp_so_define_la_LDFLAGS = \
	$(FORCE_SHARED_LIB_OPTIONS)

libtp_so_c_provider_la_SOURCES = \
	tp-so_c-provider.c \
	tp-so_c.h
libtp_so_c_provider_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)

libtp_so_c_define_la_SOURCES = \
	tp-so_c-define.c \
	tp-so_c.h
libtp_so_c_define_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)

# static archives
libtp_a_provider_la_SOURCES = \
	tp-a-provider.cpp \
	tp-a.h

libtp_a_define_la_SOURCES = \
	tp-a-define.cpp \
	tp-a.h

libtp_a_c_provider_la_SOURCES = \
	tp-a_c-provider.c \
	tp-a_c.h

libtp_a_c_define_la_SOURCES = \
	tp-a_c-define.c \
	tp-a_c.h


noinst_PROGRAMS = gen-ust-events-constructor \
	uses_heap
gen_ust_events_constructor_SOURCES = main.cpp \
	01-tp-before-define.cpp \
	02-define-tp.cpp \
	03-tp-after-define.cpp \
	04-tp-provider.cpp \
	05-tp-after-provider.cpp \
	obj.cpp \
	obj.h \
	tp.h
gen_ust_events_constructor_LDADD = $(UST_LIBS) \
		$(builddir)/libtp-so-define.la \
		$(builddir)/libtp-so-provider.la \
		$(builddir)/libtp-so_c-define.la \
		$(builddir)/libtp-so_c-provider.la \
		$(builddir)/libtp-a-define.la \
		$(builddir)/libtp-a-provider.la \
		$(builddir)/libtp-a_c-define.la \
		$(builddir)/libtp-a_c-provider.la \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS)

uses_heap_SOURCES = uses_heap.cpp
endif
