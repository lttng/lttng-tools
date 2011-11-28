AM_CPPFLAGS = -I$(top_srcdir)/include \
			  -DINSTALL_BIN_PATH=\""$(bindir)"\" \
			  -DINSTALL_LIB_PATH=\""$(libdir)"\"

AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = lttng-sessiond

if COMPAT_EPOLL
COMPAT=compat/compat-epoll.c
else
COMPAT=compat/compat-poll.c
endif

lttng_sessiond_SOURCES = utils.c utils.h \
                       hashtable.c hashtable.h \
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
                       ../hashtable/rculfhash.c \
                       ../hashtable/rculfhash.h \
                       ../hashtable/hash.c ../hashtable/hash.h

if HAVE_LIBLTTNG_UST_CTL
lttng_sessiond_SOURCES += trace-ust.c ust-app.c ust-consumer.c ust-consumer.h
endif

# Add main.c at the end for compile order
lttng_sessiond_SOURCES += lttng-sessiond.h main.c

# link on liblttngctl for check if sessiond is already alive.
lttng_sessiond_LDADD = -lrt -lurcu-common -lurcu \
		 $(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la \
		 $(top_builddir)/libkernelctl/libkernelctl.la \
		 $(top_builddir)/liblttngctl/liblttngctl.la

if HAVE_LIBLTTNG_UST_CTL
lttng_sessiond_LDADD += -llttng-ust-ctl
endif
