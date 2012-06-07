AM_CPPFLAGS = -DINSTALL_BIN_PATH=\""$(lttnglibexecdir)"\" \
			  -DINSTALL_LIB_PATH=\""$(libdir)"\"

AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = lttng-sessiond

lttng_sessiond_SOURCES = utils.c utils.h \
                       trace-kernel.c trace-kernel.h \
                       kernel.c kernel.h \
                       ust-ctl.h ust-app.h trace-ust.h \
                       context.c context.h \
                       channel.c channel.h \
                       event.c event.h \
                       shm.c shm.h \
                       session.c session.h \
                       modprobe.c modprobe.h kern-modules.h \
                       lttng-ust-ctl.h lttng-ust-abi.h \
                       fd-limit.c fd-limit.h \
                       kernel-consumer.c kernel-consumer.h

if HAVE_LIBLTTNG_UST_CTL
lttng_sessiond_SOURCES += trace-ust.c ust-app.c ust-consumer.c ust-consumer.h
endif

# Add main.c at the end for compile order
lttng_sessiond_SOURCES += lttng-sessiond.h main.c

# link on liblttngctl for check if sessiond is already alive.
lttng_sessiond_LDADD = -lrt -lurcu-common -lurcu \
		$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/kernel-ctl/libkernel-ctl.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la \
		$(top_builddir)/src/common/libcommon.la \
		$(top_builddir)/src/common/compat/libcompat.la

if HAVE_LIBLTTNG_UST_CTL
lttng_sessiond_LDADD += -llttng-ust-ctl
endif
