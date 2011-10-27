AM_CPPFLAGS = -I$(top_srcdir)/include \
			  -DINSTALL_BIN_PATH=\""$(bindir)"\"

AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ltt-sessiond

if COMPAT_EPOLL
COMPAT=compat/compat-epoll.c
else
COMPAT=compat/compat-poll.c
endif

ltt_sessiond_SOURCES = utils.c utils.h \
                       compat/poll.h $(COMPAT) \
                       trace-kernel.c trace-kernel.h \
                       kernel-ctl.c kernel-ctl.h \
		       ust-ctl.h ust-app.h trace-ust.h \
                       context.c context.h \
                       channel.c channel.h \
                       event.c event.h \
                       futex.c futex.h \
                       shm.c shm.h \
                       session.c session.h \
                       ltt-sessiond.h main.c \
                       ../hashtable/rculfhash.c \
                       ../hashtable/rculfhash.h

if LTTNG_TOOLS_HAVE_UST
ltt_sessiond_SOURCES += \
                       trace-ust.c \
                       ust-app.c
endif

# link on liblttngctl for check if sessiond is already alive.
ltt_sessiond_LDADD = -lrt \
		 $(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la \
		 $(top_builddir)/libkernelctl/libkernelctl.la \
		 $(top_builddir)/liblttngctl/liblttngctl.la

if LTTNG_TOOLS_HAVE_UST
ltt_sessiond_LDADD += -llttng-ust-comm -lustctl
endif
