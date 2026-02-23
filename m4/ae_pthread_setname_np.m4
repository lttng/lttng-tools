# SPDX-FileCopyrightText: 2020 Michael Jeanson <mjeanson@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH LicenseRef-Autoconf-exception-macro
#
# SYNOPSIS
#
#   AE_PTHREAD_SETNAME_NP
#

#serial 2

AC_DEFUN([AE_PTHREAD_SETNAME_NP], [
AC_REQUIRE([AX_PTHREAD])
AC_LANG_PUSH([C])

ae_pthread_setname_np_save_LDFLAGS="$LDFLAGS"
ae_pthread_setname_np_save_LIBS="$LIBS"
LDFLAGS="$LDFLAGS $PTHREAD_CFLAGS"
LIBS="$LIBS $PTHREAD_LIBS"

# GLIBC >= 2.12, Solaris >= 11.3, FreeBSD >= 12.2
AC_MSG_CHECKING(for pthread_setname_np(pthread_t, const char*))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <pthread.h>
         #ifdef __FreeBSD__
         #include <pthread_np.h>
         #endif]],
        [pthread_setname_np(pthread_self(), "example")])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_PTHREAD_SETNAME_NP_WITH_TID,1,
        [Have function pthread_setname_np(pthread_t, const char*)])],
    [AC_MSG_RESULT(no)])

# MacOS X >= 10.6, iOS >= 3.2
AC_MSG_CHECKING(for pthread_setname_np(const char*))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <pthread.h>
         #ifdef __FreeBSD__
         #include <pthread_np.h>
         #endif]],
        [pthread_setname_np("example")])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_PTHREAD_SETNAME_NP_WITHOUT_TID,1,
        [Have function pthread_setname_np(const char*)])],
    [AC_MSG_RESULT(no)])

# FreeBSD
AC_MSG_CHECKING(for pthread_set_name_np(pthread_t, const char*))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <pthread.h>
         #ifdef __FreeBSD__
         #include <pthread_np.h>
         #endif]],
        [pthread_set_name_np(pthread_self(), "example")])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_PTHREAD_SET_NAME_NP_WITH_TID,1,
        [Have function pthread_set_name_np(pthread_t, const char*)])],
    [AC_MSG_RESULT(no)])

LDFLAGS=$ae_pthread_setname_np_save_LDFLAGS
LIBS=$ae_pthread_setname_np_save_LIBS

AC_LANG_POP
])dnl AE_PTHREAD_SETNAME_NP
