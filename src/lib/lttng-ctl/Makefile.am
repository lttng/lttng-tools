SUBDIRS = filter

AM_CPPFLAGS += -I$(srcdir) -I$(builddir)

lib_LTLIBRARIES = liblttng-ctl.la

liblttng_ctl_la_SOURCES = lttng-ctl.c snapshot.c lttng-ctl-helper.h \
		lttng-ctl-health.c save.c load.c deprecated-symbols.c \
		channel.c

liblttng_ctl_la_LDFLAGS = \
		$(LT_NO_UNDEFINED)

liblttng_ctl_la_LIBADD = \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/libcommon.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la \
		$(top_builddir)/src/lib/lttng-ctl/filter/libfilter.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ctl.pc
