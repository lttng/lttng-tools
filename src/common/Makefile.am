AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = compat health hashtable kernel-ctl sessiond-comm relayd \
		  kernel-consumer ust-consumer testpoint index config \
		  consumer

AM_CFLAGS = -fno-strict-aliasing

noinst_HEADERS = lttng-kernel.h defaults.h macros.h error.h futex.h \
				 uri.h utils.h lttng-kernel-old.h \
				 align.h bitfield.h bug.h

# Common library
noinst_LTLIBRARIES = libcommon.la
EXTRA_DIST = mi_lttng.xsd

libcommon_la_SOURCES = error.h error.c utils.c utils.h runas.c runas.h \
                       common.h futex.c futex.h uri.c uri.h defaults.c \
                       pipe.c pipe.h readwrite.c readwrite.h \
                       mi-lttng.h mi-lttng.c \
                       daemonize.c daemonize.h \
                       sessiond-comm/unix.c sessiond-comm/unix.h

libcommon_la_LIBADD = \
		-luuid \
		-lrt \
		$(top_builddir)/src/common/config/libconfig.la

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
		cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
		rm -f $(builddir)/$$script; \
		done; \
	fi
