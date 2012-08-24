SUBDIRS = filter

lib_LTLIBRARIES = liblttng-ctl.la

liblttng_ctl_la_SOURCES = lttng-ctl.c

liblttng_ctl_la_LIBADD = \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/libcommon.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la \
		$(top_builddir)/src/lib/lttng-ctl/filter/libfilter.la
