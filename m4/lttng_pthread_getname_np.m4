# SYNOPSIS
#
#   LTTNG_PTHREAD_GETNAME_NP
#
# LICENSE
#
#   Copyright (c) 2020 Michael Jeanson <mjeanson@efficios.com>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 2 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <https://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

AC_DEFUN([LTTNG_PTHREAD_GETNAME_NP], [
AC_REQUIRE([AX_PTHREAD])
AC_LANG_PUSH([C])

lttng_pthread_getname_np_save_LDFLAGS="$LDFLAGS"
lttng_pthread_getname_np_save_LIBS="$LIBS"
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
         #define LTTNG_PTHREAD_NAMELEN 16
         char lttng_pthread_name[LTTNG_PTHREAD_NAMELEN];]],
        [pthread_getname_np(pthread_self(), lttng_pthread_name, LTTNG_PTHREAD_NAMELEN)])],
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
         #define LTTNG_PTHREAD_NAMELEN 16
         char lttng_pthread_name[LTTNG_PTHREAD_NAMELEN];]],
        [pthread_getname_np(lttng_pthread_name, LTTNG_PTHREAD_NAMELEN)])],
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
         #define LTTNG_PTHREAD_NAMELEN 16
         char lttng_pthread_name[LTTNG_PTHREAD_NAMELEN];]],
        [pthread_get_name_np(pthread_self(), lttng_pthread_name, LTTNG_PTHREAD_NAMELEN)])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_PTHREAD_GET_NAME_NP_WITH_TID,1,
        [Have function pthread_get_name_np(pthread_t, char*, size_t)])],
    [AC_MSG_RESULT(no)])

LDFLAGS=$lttng_pthread_getname_np_save_LDFLAGS
LIBS=$lttng_pthread_getname_np_save_LIBS

AC_LANG_POP
])dnl LTTNG_PTHREAD_GETNAME_NP
