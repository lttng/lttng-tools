# SPDX-FileCopyrightText: 2020 Michael Jeanson <mjeanson@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH LicenseRef-Autoconf-exception-macro
#
# SYNOPSIS
#
#   AE_PTHREAD_GETNAME_NP
#

#serial 2

AC_DEFUN([AE_PTHREAD_GETNAME_NP], [
AC_REQUIRE([AX_PTHREAD])
AC_LANG_PUSH([C])

ae_pthread_getname_np_save_LDFLAGS="$LDFLAGS"
ae_pthread_getname_np_save_LIBS="$LIBS"
LDFLAGS="$LDFLAGS $PTHREAD_CFLAGS"
LIBS="$LIBS $PTHREAD_LIBS"

# GLIBC >= 2.12, Solaris >= 11.3, FreeBSD >= 12.2, MacOS X >= 10.6, iOS >= 3.2
AC_MSG_CHECKING(for pthread_getname_np(pthread_t, char*, size_t))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <pthread.h>
         #ifdef __FreeBSD__
         #include <pthread_np.h>
         #endif
         #define AE_PTHREAD_NAMELEN 16
         char ae_pthread_name[AE_PTHREAD_NAMELEN];]],
        [pthread_getname_np(pthread_self(), ae_pthread_name, AE_PTHREAD_NAMELEN)])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_PTHREAD_GETNAME_NP_WITH_TID,1,
        [Have function pthread_getname_np(pthread_t, char*, size_t)])],
    [AC_MSG_RESULT(no)])

AC_MSG_CHECKING(for pthread_getname_np(char*, size_t))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <pthread.h>
         #ifdef __FreeBSD__
         #include <pthread_np.h>
         #endif
         #define AE_PTHREAD_NAMELEN 16
         char ae_pthread_name[AE_PTHREAD_NAMELEN];]],
        [pthread_getname_np(ae_pthread_name, AE_PTHREAD_NAMELEN)])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_PTHREAD_GETNAME_NP_WITHOUT_TID,1,
        [Have function pthread_getname_np(char*, size_t)])],
    [AC_MSG_RESULT(no)])

# FreeBSD
AC_MSG_CHECKING(for pthread_get_name_np(pthread_t, char*, size_t))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <pthread.h>
         #ifdef __FreeBSD__
         #include <pthread_np.h>
         #endif
         #define AE_PTHREAD_NAMELEN 16
         char ae_pthread_name[AE_PTHREAD_NAMELEN];]],
        [pthread_get_name_np(pthread_self(), ae_pthread_name, AE_PTHREAD_NAMELEN)])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_PTHREAD_GET_NAME_NP_WITH_TID,1,
        [Have function pthread_get_name_np(pthread_t, char*, size_t)])],
    [AC_MSG_RESULT(no)])

LDFLAGS=$ae_pthread_getname_np_save_LDFLAGS
LIBS=$ae_pthread_getname_np_save_LIBS

AC_LANG_POP
])dnl AE_PTHREAD_GETNAME_NP
