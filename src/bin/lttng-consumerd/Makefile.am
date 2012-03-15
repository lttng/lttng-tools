AM_CPPFLAGS =

lttnglibexec_PROGRAMS = lttng-consumerd

lttng_consumerd_SOURCES = lttng-consumerd.c lttng-consumerd.h

lttng_consumerd_LDADD = \
	   $(top_builddir)/src/common/kernel-ctl/libkernel-ctl.la \
	   $(top_builddir)/src/common/libconsumer.la \
	   $(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
	   $(top_builddir)/src/common/libcommon.la

if HAVE_LIBLTTNG_UST_CTL
lttng_consumerd_LDADD += -llttng-ust-ctl
endif
