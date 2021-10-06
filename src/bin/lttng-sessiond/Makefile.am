# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS +=-DINSTALL_BIN_PATH=\""$(lttnglibexecdir)"\" \
	-DINSTALL_LIB_PATH=\""$(libdir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

noinst_LTLIBRARIES = liblttng-sessiond-common.la

liblttng_sessiond_common_la_SOURCES = utils.cpp utils.h \
                       trace-kernel.cpp trace-kernel.h \
                       kernel.cpp kernel.h \
                       ust-app.h ust-sigbus.h trace-ust.h notify-apps.h \
                       lttng-ust-ctl.h lttng-ust-abi.h lttng-ust-error.h \
                       ust-ctl-internal.h ust-abi-internal.h ust-error-internal.h \
                       ust-registry.h \
                       condition-internal.cpp condition-internal.h \
                       context.cpp context.h \
                       channel.cpp channel.h \
                       event.cpp event.h \
                       consumer.cpp consumer.h \
                       session.cpp session.h \
                       modprobe.cpp modprobe.h kern-modules.h \
                       fd-limit.cpp fd-limit.h \
                       kernel-consumer.cpp kernel-consumer.h \
                       consumer.h \
                       health-sessiond.h \
                       cmd.cpp cmd.h \
                       buffer-registry.cpp buffer-registry.h \
                       testpoint.h ht-cleanup.cpp ht-cleanup.h \
                       snapshot.cpp snapshot.h \
                       agent.cpp agent.h \
                       save.h save.cpp \
                       lttng-syscall.h lttng-syscall.cpp \
                       notification-thread.h notification-thread.cpp \
                       notification-thread-internal.h \
                       notification-thread-commands.h notification-thread-commands.cpp \
                       notification-thread-events.h notification-thread-events.cpp \
                       sessiond-config.h sessiond-config.cpp \
                       rotate.h rotate.cpp \
                       rotation-thread.h rotation-thread.cpp \
                       timer.cpp timer.h \
                       globals.cpp \
                       thread-utils.cpp \
                       process-utils.cpp \
                       thread.cpp thread.h \
                       health.cpp \
                       client.cpp client.h \
                       dispatch.cpp dispatch.h \
                       register.cpp register.h \
                       manage-apps.cpp manage-apps.h \
                       manage-kernel.cpp manage-kernel.h \
                       manage-consumer.cpp manage-consumer.h \
                       clear.cpp clear.h \
                       tracker.cpp tracker.h \
                       event-notifier-error-accounting.cpp event-notifier-error-accounting.h \
                       action-executor.cpp action-executor.h\
                       trigger-error-query.cpp

if HAVE_LIBLTTNG_UST_CTL
liblttng_sessiond_common_la_SOURCES += trace-ust.cpp ust-registry.cpp ust-app.cpp \
			ust-consumer.cpp ust-consumer.h notify-apps.cpp \
			ust-metadata.cpp ust-clock.h agent-thread.cpp agent-thread.h \
			ust-field-utils.h ust-field-utils.cpp \
			ust-sigbus.cpp
endif

# link on liblttngctl for check if sessiond is already alive.
liblttng_sessiond_common_la_LIBADD = $(URCU_LIBS) $(KMOD_LIBS) \
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
liblttng_sessiond_common_la_LIBADD += $(UST_CTL_LIBS)
endif

bin_PROGRAMS = lttng-sessiond

lttng_sessiond_SOURCES = lttng-sessiond.h main.cpp

lttng_sessiond_LDFLAGS = -rdynamic

lttng_sessiond_LDADD = liblttng-sessiond-common.la
