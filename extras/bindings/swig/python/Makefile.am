# SPDX-License-Identifier: GPL-2.0-only

lttng.i: lttng.i.in
	$(SED) "s/LTTNG_VERSION_STR/LTTng $(PACKAGE_VERSION)/g" < $(srcdir)/lttng.i.in >lttng.i

# Some versions of SWIG (like 3.0.12) generate code where a parameter called
# `swig_this` shadows a global of the same name.  Later versions (like 4.0.1)
# have renamed this global to `Swig_This_global`.
#
# Disable some warning flags for that file.
AM_CFLAGS += \
	-Wno-cast-function-type \
	-Wno-missing-field-initializers \
	-Wno-null-dereference \
	-Wno-redundant-decls \
	-Wno-shadow \
	-Wno-unused-parameter

# Swig regularily changes and generates code that results warnings which break
# Werror builds. Disable that option for this sub-project.
AM_CFLAGS += -Wno-error

AM_CPPFLAGS += $(PYTHON_INCLUDE)

EXTRA_DIST = lttng.i.in
nodist_python_PYTHON = lttng.py
pyexec_LTLIBRARIES = _lttng.la

MAINTAINERCLEANFILES = lttng_wrap.c lttng.py

nodist__lttng_la_SOURCES = lttng_wrap.c
_lttng_la_LDFLAGS = -module
_lttng_la_LIBADD = 	$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la 		\
			$(top_builddir)/src/common/libsessiond-comm.la		\
			$(top_builddir)/src/common/libcommon-gpl.la

# Use this fake source file to force the link mode of the library
# from gcc to g++. The library contains only C code, but depends on
# libstdc++.
nodist_EXTRA__lttng_la_SOURCES = dummy.cpp

lttng_wrap.c: lttng.i
	$(SWIG) -python -I. -I$(top_srcdir)/src/common/sessiond-comm lttng.i

CLEANFILES = lttng.i lttng.py lttng_wrap.c lttng.pyc
