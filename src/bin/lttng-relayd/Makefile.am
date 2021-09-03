# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -DINSTALL_BIN_PATH=\""$(lttnglibexecdir)"\" \
	-DINSTALL_LIB_PATH=\""$(libdir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

bin_PROGRAMS = lttng-relayd

lttng_relayd_SOURCES = main.cpp lttng-relayd.h utils.h utils.cpp cmd.h \
                       index.cpp index.h live.cpp live.h ctf-trace.cpp ctf-trace.h \
                       cmd-2-1.cpp cmd-2-1.h \
                       cmd-2-2.cpp cmd-2-2.h \
                       cmd-2-4.cpp cmd-2-4.h \
                       cmd-2-11.cpp cmd-2-11.h \
                       health-relayd.cpp health-relayd.h \
                       lttng-viewer-abi.h testpoint.h \
                       viewer-stream.h viewer-stream.cpp \
                       session.cpp session.h \
                       stream.cpp stream.h \
                       connection.cpp connection.h \
                       viewer-session.cpp viewer-session.h \
                       tracefile-array.cpp tracefile-array.h \
                       tcp_keep_alive.cpp tcp_keep_alive.h \
                       sessiond-trace-chunks.cpp sessiond-trace-chunks.h \
                       backward-compatibility-group-by.cpp backward-compatibility-group-by.h

# link on liblttngctl for check if relayd is already alive.
lttng_relayd_LDADD = $(URCU_LIBS) \
		$(top_builddir)/src/common/libcommon.la \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la \
		$(top_builddir)/src/common/compat/libcompat.la \
		$(top_builddir)/src/common/index/libindex.la \
		$(top_builddir)/src/common/health/libhealth.la \
		$(top_builddir)/src/common/config/libconfig.la \
		$(top_builddir)/src/common/testpoint/libtestpoint.la \
		$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la
