# SPDX-License-Identifier: GPL-2.0-only

noinst_LTLIBRARIES = libcompat.la

if COMPAT_EPOLL
COMPAT=compat-epoll.c
else
COMPAT=compat-poll.c
endif

libcompat_la_SOURCES = poll.h fcntl.h endian.h mman.h dirent.h \
		socket.h compat-fcntl.c tid.h \
		getenv.h string.h paths.h pthread.h netdb.h $(COMPAT) \
		time.h directory-handle.h directory-handle.c path.h
