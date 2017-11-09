AM_CPPFLAGS +=-DINSTALL_BIN_PATH=\""$(lttnglibexecdir)"\" \
	-DINSTALL_LIB_PATH=\""$(libdir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

bin_PROGRAMS = lttng-sessiond

lttng_sessiond_SOURCES = utils.c utils.h \
                       trace-kernel.c trace-kernel.h \
                       kernel.c kernel.h \
                       ust-ctl.h ust-app.h trace-ust.h ust-thread.h \
                       ust-registry.h \
                       context.c context.h \
                       channel.c channel.h \
                       event.c event.h \
                       shm.c shm.h \
                       consumer.c consumer.h \
                       session.c session.h \
                       modprobe.c modprobe.h kern-modules.h \
                       lttng-ust-ctl.h lttng-ust-abi.h lttng-ust-error.h \
                       fd-limit.c fd-limit.h \
                       kernel-consumer.c kernel-consumer.h \
                       consumer.h \
                       health-sessiond.h \
                       cmd.c cmd.h \
                       buffer-registry.c buffer-registry.h \
                       testpoint.h ht-cleanup.c ht-cleanup.h \
                       snapshot.c snapshot.h \
                       agent.c agent.h \
                       save.h save.c \
                       load-session-thread.h load-session-thread.c \
                       syscall.h syscall.c \
                       notification-thread.h notification-thread.c \
                       notification-thread-commands.h notification-thread-commands.c \
                       notification-thread-events.h notification-thread-events.c \
                       sessiond-config.h sessiond-config.c

if HAVE_LIBLTTNG_UST_CTL
lttng_sessiond_SOURCES += trace-ust.c ust-registry.c ust-app.c \
			ust-consumer.c ust-consumer.h ust-thread.c \
			ust-metadata.c ust-clock.h agent-thread.c agent-thread.h
endif

# Add main.c at the end for compile order
lttng_sessiond_SOURCES += lttng-sessiond.h main.c

# link on liblttngctl for check if sessiond is already alive.
lttng_sessiond_LDADD = -lurcu-common -lurcu $(KMOD_LIBS) \
		$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/kernel-ctl/libkernel-ctl.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la \
		$(top_builddir)/src/common/libcommon.la \
		$(top_builddir)/src/common/compat/libcompat.la \
		$(top_builddir)/src/common/relayd/librelayd.la \
		$(top_builddir)/src/common/testpoint/libtestpoint.la \
		$(top_builddir)/src/common/health/libhealth.la \
		$(top_builddir)/src/common/config/libconfig.la \
		$(top_builddir)/src/common/string-utils/libstring-utils.la


if HAVE_LIBLTTNG_UST_CTL
lttng_sessiond_LDADD += -llttng-ust-ctl
endif
