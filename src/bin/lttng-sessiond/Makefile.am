# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS +=-DINSTALL_BIN_PATH=\""$(lttnglibexecdir)"\" \
	-DINSTALL_LIB_PATH=\""$(libdir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

noinst_LTLIBRARIES = liblttng-sessiond-common.la

liblttng_sessiond_common_la_SOURCES = utils.cpp utils.hpp \
                       trace-kernel.cpp trace-kernel.hpp \
                       kernel.cpp kernel.hpp \
                       ust-app.hpp ust-sigbus.hpp trace-ust.hpp notify-apps.hpp \
                       lttng-ust-ctl.hpp lttng-ust-abi.hpp lttng-ust-error.hpp \
                       ust-ctl-internal.hpp ust-abi-internal.hpp ust-error-internal.hpp \
                       ust-registry.hpp \
                       condition-internal.cpp condition-internal.hpp \
                       context.cpp context.hpp \
                       channel.cpp channel.hpp \
                       event.cpp event.hpp \
                       consumer.cpp consumer.hpp \
                       session.cpp session.hpp \
                       modprobe.cpp modprobe.hpp kern-modules.hpp \
                       fd-limit.cpp fd-limit.hpp \
                       kernel-consumer.cpp kernel-consumer.hpp \
                       consumer.hpp \
                       health-sessiond.hpp \
                       cmd.cpp cmd.hpp \
                       buffer-registry.cpp buffer-registry.hpp \
                       testpoint.hpp \
                       snapshot.cpp snapshot.hpp \
                       agent.cpp agent.hpp \
                       save.hpp save.cpp \
                       lttng-syscall.hpp lttng-syscall.cpp \
                       notification-thread.hpp notification-thread.cpp \
                       notification-thread-internal.hpp \
                       notification-thread-commands.hpp notification-thread-commands.cpp \
                       notification-thread-events.hpp notification-thread-events.cpp \
                       sessiond-config.hpp sessiond-config.cpp \
                       rotation-thread.hpp rotation-thread.cpp \
                       timer.cpp timer.hpp \
                       globals.cpp \
                       thread-utils.cpp \
                       process-utils.cpp \
                       thread.cpp thread.hpp \
                       health.cpp \
                       client.cpp client.hpp \
                       dispatch.cpp dispatch.hpp \
                       register.cpp register.hpp \
                       manage-apps.cpp manage-apps.hpp \
                       manage-kernel.cpp manage-kernel.hpp \
                       manage-consumer.cpp manage-consumer.hpp \
                       clear.cpp clear.hpp \
                       tracker.cpp tracker.hpp \
                       event-notifier-error-accounting.cpp event-notifier-error-accounting.hpp \
                       action-executor.cpp action-executor.hpp\
                       trigger-error-query.cpp \
                       field.hpp field.cpp \
                       clock-class.hpp clock-class.cpp \
                       event-class.hpp event-class.cpp \
                       stream-class.hpp stream-class.cpp \
                       trace-class.hpp trace-class.cpp

if HAVE_LIBLTTNG_UST_CTL
liblttng_sessiond_common_la_SOURCES += trace-ust.cpp ust-registry.cpp ust-app.cpp \
			ust-consumer.cpp ust-consumer.hpp notify-apps.cpp \
			ust-clock-class.hpp ust-clock-class.cpp \
			agent-thread.cpp agent-thread.hpp \
			ust-field-convert.cpp ust-field-convert.hpp \
			ust-sigbus.cpp \
			ust-registry-session.cpp ust-registry-session.hpp \
			ust-registry-event.cpp ust-registry-event.hpp \
			ust-registry-channel.cpp ust-registry-channel.hpp \
			ust-registry-session-uid.cpp ust-registry-session-uid.hpp \
			ust-registry-session-pid.cpp ust-registry-session-pid.hpp \
			tsdl-trace-class-visitor.cpp tsdl-trace-class-visitor.hpp \
			ctf2-trace-class-visitor.cpp ctf2-trace-class-visitor.hpp
endif

# link on liblttngctl for check if sessiond is already alive.
liblttng_sessiond_common_la_LIBADD = $(URCU_LIBS) $(KMOD_LIBS) \
		$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		$(top_builddir)/src/common/libsessiond-comm.la \
		$(top_builddir)/src/common/libkernel-ctl.la \
		$(top_builddir)/src/common/libcommon-gpl.la \
		$(top_builddir)/src/common/libcompat.la \
		$(top_builddir)/src/common/librelayd.la \
		$(top_builddir)/src/common/libtestpoint.la \
		$(top_builddir)/src/common/libhealth.la \
		$(top_builddir)/src/common/libconfig.la \
		$(top_builddir)/src/common/libstring-utils.la


if HAVE_LIBLTTNG_UST_CTL
liblttng_sessiond_common_la_LIBADD += $(UST_CTL_LIBS)
endif

bin_PROGRAMS = lttng-sessiond

lttng_sessiond_SOURCES = lttng-sessiond.hpp main.cpp

lttng_sessiond_LDFLAGS = -rdynamic

lttng_sessiond_LDADD = liblttng-sessiond-common.la
