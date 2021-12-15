# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -DINSTALL_BIN_PATH=\""$(lttnglibexecdir)"\" \
	-DINSTALL_LIB_PATH=\""$(libdir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

bin_PROGRAMS = lttng-relayd

lttng_relayd_SOURCES = main.cpp lttng-relayd.hpp utils.hpp utils.cpp cmd.hpp \
                       index.cpp index.hpp live.cpp live.hpp ctf-trace.cpp ctf-trace.hpp \
                       cmd-2-1.cpp cmd-2-1.hpp \
                       cmd-2-2.cpp cmd-2-2.hpp \
                       cmd-2-4.cpp cmd-2-4.hpp \
                       cmd-2-11.cpp cmd-2-11.hpp \
                       health-relayd.cpp health-relayd.hpp \
                       lttng-viewer-abi.hpp testpoint.hpp \
                       viewer-stream.hpp viewer-stream.cpp \
                       session.cpp session.hpp \
                       stream.cpp stream.hpp \
                       connection.cpp connection.hpp \
                       viewer-session.cpp viewer-session.hpp \
                       tracefile-array.cpp tracefile-array.hpp \
                       tcp_keep_alive.cpp tcp_keep_alive.hpp \
                       sessiond-trace-chunks.cpp sessiond-trace-chunks.hpp \
                       backward-compatibility-group-by.cpp backward-compatibility-group-by.hpp

# link on liblttngctl for check if relayd is already alive.
lttng_relayd_LDADD = $(URCU_LIBS) \
		$(top_builddir)/src/common/libcommon-gpl.la \
		$(top_builddir)/src/common/libsessiond-comm.la \
		$(top_builddir)/src/common/libcompat.la \
		$(top_builddir)/src/common/libindex.la \
		$(top_builddir)/src/common/libhealth.la \
		$(top_builddir)/src/common/libtestpoint.la
