AM_CFLAGS = -I. -O2 -g -I../../../include
AM_LDFLAGS =

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

UTILS=

noinst_PROGRAMS = health_check

health_check_SOURCES = health_check.c $(UTILS)
health_check_LDADD = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		     $(top_builddir)/src/common/libcommon.la

noinst_SCRIPTS =
EXTRA_DIST =
