noinst_LTLIBRARIES = libcompat.la

if COMPAT_EPOLL
COMPAT=compat-epoll.c
else
COMPAT=compat-poll.c
endif

libcompat_la_SOURCES = poll.h fcntl.h endian.h mman.h dirent.h \
		socket.h compat-fcntl.c uuid.h tid.h \
		getenv.h string.h prctl.h paths.h netdb.h $(COMPAT) \
		time.h
