AC_DEFUN(AC_CHECK_GTHREAD_SUPPORTED,
[AC_ARG_ENABLE(gthreadtest, [  --disable-gthread-test      do not confirm that gthreads works],
		    , enable_gthreadtest=yes)

  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

  if test x$PKG_CONFIG = x; then
    AC_MSG_ERROR(pkg-config not found)
  fi

  CFLAGS=`$PKG_CONFIG --cflags glib-2.0 gthread-2.0`
  LIBS=`$PKG_CONFIG --libs glib-2.0 gthread-2.0`

  AC_MSG_CHECKING(for working gthreads)

  gthread_supported="yes"

      rm -f conf.gthreadtest
      AC_TRY_RUN([
#include <glib.h>

int 
main ()
{
	g_thread_init (NULL);

	return !g_thread_supported (); /* 0 is true, 1 is false */
}
],,gthread_supported="no",[echo $ac_n "cross compiling; assumed OK... $ac_c"])

  if test x$gthread_supported = xno; then
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(The glib thread library does not support your system.  Marmot requires this in order to work properly.)
  else
    AC_MSG_RESULT(yes)
  fi

  rm -f conf.gthreadtest
])
