# ===========================================================================
#       http://www.gnu.org/software/autoconf-archive/ax_prog_javah.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PROG_JAVAH
#
# DESCRIPTION
#
#   AX_PROG_JAVAH tests the availability of the javah header generator and
#   looks for the jni.h header file. If available, JAVAH is set to the full
#   path of javah and CPPFLAGS is updated accordingly.
#
# LICENSE
#
#   Copyright (c) 2008 Luc Maisonobe <luc@spaceroots.org>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 7

AU_ALIAS([AC_PROG_JAVAH], [AX_PROG_JAVAH])
AC_DEFUN([AX_PROG_JAVAH],[
AC_REQUIRE([AC_CANONICAL_BUILD])dnl
AC_REQUIRE([AC_PROG_CPP])dnl
AC_PATH_PROG(JAVAH,javah)
AS_IF([test -n "$ac_cv_path_JAVAH"],
      [
        AC_TRY_CPP([#include <jni.h>],,[
        ac_save_CPPFLAGS="$CPPFLAGS"
        ax_prog_javah_bin_dir=`AS_DIRNAME([$ac_cv_path_JAVAH])`
        ac_dir="`AS_DIRNAME([$ax_prog_javah_bin])`/include"
        AS_CASE([$build_os],
                [cygwin*],
                [ac_machdep=win32],
                [ac_machdep=`AS_ECHO($build_os) | sed 's,[[-0-9]].*,,'`])
        CPPFLAGS="$ac_save_CPPFLAGS -I$ac_dir -I$ac_dir/$ac_machdep"
        AC_TRY_CPP([#include <jni.h>],
                   ac_save_CPPFLAGS="$CPPFLAGS",
                   AC_MSG_WARN([unable to include <jni.h>]))
        CPPFLAGS="$ac_save_CPPFLAGS"])
      ])
])
