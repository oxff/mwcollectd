# mwcollectd autoconf input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AC_PREREQ(2.59)
AC_INIT([mwcollectd], [4.0.0-rc1], [gw@mwcollect.org])
AM_INIT_AUTOMAKE([mwcollectd], [4.0.0-rc1])

AC_PREFIX_DEFAULT(/opt/mwcollectd)
AC_DEFINE_UNQUOTED(PREFIX, "$prefix")

AC_REVISION([1])

AC_PROG_CXX
AC_PROG_LIBTOOL
AC_LANG_CPLUSPLUS

AC_DEFUN([AX_CHECK_COMPILER_FLAGS],
[AC_PREREQ(2.59) dnl for _AC_LANG_PREFIX
AC_MSG_CHECKING([whether _AC_LANG compiler accepts $1])
dnl Some hackery here since AC_CACHE_VAL can't handle a non-literal varname:
AS_LITERAL_IF([$1],
  [AC_CACHE_VAL(AS_TR_SH(ax_cv_[]_AC_LANG_ABBREV[]_flags_[$1]), [
      ax_save_FLAGS=$[]_AC_LANG_PREFIX[]FLAGS
      _AC_LANG_PREFIX[]FLAGS="$1"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
        AS_TR_SH(ax_cv_[]_AC_LANG_ABBREV[]_flags_[$1])=yes,
        AS_TR_SH(ax_cv_[]_AC_LANG_ABBREV[]_flags_[$1])=no)
      _AC_LANG_PREFIX[]FLAGS=$ax_save_FLAGS])],
  [ax_save_FLAGS=$[]_AC_LANG_PREFIX[]FLAGS
   _AC_LANG_PREFIX[]FLAGS="$1"
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
     eval AS_TR_SH(ax_cv_[]_AC_LANG_ABBREV[]_flags_[$1])=yes,
     eval AS_TR_SH(ax_cv_[]_AC_LANG_ABBREV[]_flags_[$1])=no)
   _AC_LANG_PREFIX[]FLAGS=$ax_save_FLAGS])
eval ax_check_compiler_flags=$AS_TR_SH(ax_cv_[]_AC_LANG_ABBREV[]_flags_[$1])
AC_MSG_RESULT($ax_check_compiler_flags)
if test "x$ax_check_compiler_flags" = xyes; then
	m4_default([$2], :)
else
	m4_default([$3], :)
fi
])dnl AX_CHECK_COMPILER_FLAGS

AX_CHECK_COMPILER_FLAGS([-pipe], [CXXFLAGS+=" -pipe"])
AX_CHECK_COMPILER_FLAGS([-Wno-strict-aliasing], [CXXFLAGS+=" -Wno-strict-aliasing"])


AC_CHECK_HEADERS([stdint.h stdlib.h string.h strings.h unistd.h])

dnl **************************************************
dnl * libnetworkd Support                            *
dnl **************************************************
AC_ARG_WITH(libnetworkd,
    [  --with-libnetworkd=PATH	specify path to libnetworkd],
    [export PKG_CONFIG_PATH=$withval/lib/pkgconfig],
    [])
    
if pkg-config --exists libnetworkd; then
	echo linking against libnetworkd `pkg-config --modversion libnetworkd`
	LDFLAGS+=" `pkg-config --libs libnetworkd`"
	CXXFLAGS+=" `pkg-config --cflags libnetworkd`"
else
	AC_MSG_ERROR([libnetworkd not found, please give correct path or install])
fi

dnl **************************************************
dnl * python Support                                 *
dnl **************************************************


AC_SUBST([PYTHON_CPPFLAGS])
AC_SUBST([PYTHON_LDFLAGS])

do_enable_python="yes"

AC_ARG_ENABLE(python, [  --enable-python    enable python support [[default yes]]], [do_enable_python=$enableval])
AC_ARG_WITH(python3-config, [  --with-python3-config=PATH  specify path to python3-config binary],
	    [export PYTHON3_CONFIG=$withval], [export PYTHON3_CONFIG=/usr/bin/python3-config])

enable_python=${do_enable_python}

if test x"$enable_python" = "xyes"; then
	if test -x "${PYTHON3_CONFIG}"; then
		ORIG_LDFLAGS=${LDFLAGS}
		ORIG_CPPFLAGS=${CPPFLAGS}
		PYTHON_LDFLAGS=" `${PYTHON3_CONFIG} --ldflags` -L`${PYTHON3_CONFIG} --prefix`/lib"
		PYTHON_CPPFLAGS=" `${PYTHON3_CONFIG} --includes`"
		LDFLAGS+=${PYTHON_LDFLAGS}
		CPPFLAGS+=${PYTHON_CPPFLAGS}

		AC_CHECK_HEADER([Python.h],[enable_python="yes"],[enable_python=""])

		if test x"$enable_python" = "xyes"; then
			AC_CHECK_LIB([python3.1],[Py_Initialize],[enable_python="yes"],[enable_python=""])

			if test x"$enable_python" != "xyes"; then
				AC_CHECK_LIB([python3.0], [Py_Initialize], [enable_python="yes"], [enable_python=""])
			
				if test x"$enable_python" != "xyes"; then
					AC_CHECK_LIB([python3.2], [Py_Initialize], [enable_python="yes"], [enable_python=""])
				fi
			fi
		fi

		LDFLAGS=${ORIG_LDFLAGS}
		CPPFLAGS=${ORIG_CPPFLAGS}
	else
		enable_python="no"
	fi
fi

dnl **************************************************
dnl * libemu Support                           	     *
dnl **************************************************

AC_SUBST([LIBEMU_CPPFLAGS])
AC_SUBST([LIBEMU_LDFLAGS])

AC_ARG_WITH(libemu,
    [  --with-libemu=PATH	specify path to libemu],
    [export PKG_CONFIG_PATH="${withval}/lib/pkgconfig"; export LIBEMU_DIR="${withval}"],
    [])

do_enable_libemu="yes"

AC_ARG_ENABLE(libemu, [  --enable-libemu    enable libemu support [[default yes]]], [do_enable_libemu=$enableval])

enable_libemu=${do_enable_libemu}

if test x"$enable_libemu" = "xyes"; then
	if pkg-config --exists libemu; then
		ORIG_LDFLAGS=${LDFLAGS}
		ORIG_CPPFLAGS=${CPPFLAGS}
		LIBEMU_LDFLAGS=" `pkg-config --libs libemu`"
		LIBEMU_CPPFLAGS=" `pkg-config --cflags libemu`"
		LDFLAGS+=${LIBEMU_LDFLAGS}
		CPPFLAGS+=${LIBEMU_CPPFLAGS}

		AC_CHECK_HEADER([emu/emu.h],[enable_libemu="yes"],[enable_libemu=""])

		if test x"$enable_libemu" = "xyes"; then
			AC_CHECK_LIB([emu],[emu_new],[enable_libemu="yes"],[enable_libemu=""])
		fi

		LDFLAGS=${ORIG_LDFLAGS}
		CPPFLAGS=${ORIG_CPPFLAGS}

		echo linking against libemu `pkg-config --modversion libemu`
	else
		ORIG_LDFLAGS=${LDFLAGS}
		ORIG_CPPFLAGS=${CPPFLAGS}
		LIBEMU_LDFLAGS=" -L${LIBEMU_DIR}/lib -lemu"
		LIBEMU_CPPFLAGS=" -I${LIBEMU_DIR}/include"
		LDFLAGS+=${LIBEMU_LDFLAGS}
		CPPFLAGS+=${LIBEMU_CPPFLAGS}

		AC_CHECK_HEADER([emu/emu.h],[enable_libemu="yes"],[enable_libemu=""])

		if test x"$enable_libemu" = "xyes"; then
			AC_CHECK_LIB([emu],[emu_new],[enable_libemu="yes"],[enable_libemu=""])
		fi

		LDFLAGS=${ORIG_LDFLAGS}
		CPPFLAGS=${ORIG_CPPFLAGS}

		echo linking against libemu
	fi
fi

dnl **************************************************
dnl * libpg Support                           	     *
dnl **************************************************

AC_SUBST([POSTGRESQL_CXXFLAGS])
AC_SUBST([POSTGRESQL_LDFLAGS])

enable_pgsql="yes"

AC_ARG_ENABLE(pgsql, [  --enable-pgsql    enable postgresql support (default yes)], [enable_pgsql="$enableval"])

if test x"$enable_pgsql" = "xyes"; then
	AC_CHECK_HEADER([postgresql/libpq-fe.h],[enable_pgsql="yes"],[enable_pgsql=""])

	if test x"$enable_pgsql" = "xyes"; then
		AC_CHECK_LIB([pq],[PQconnectStart],[enable_pgsql="yes"],[enable_pgsql=""])

		if test x"$enable_pgsql" = "xyes"; then
			POSTGRESQL_CXXFLAGS="-I/usr/include/postgresql"
			POSTGRESQL_LDFLAGS="-lpq"
		fi
	fi
fi


dnl **************************************************
dnl * libnfq Support                           	     *
dnl **************************************************

enable_nfq="yes"

AC_ARG_ENABLE(nfq, [  --enable-nfq    enable libnetfilter_queue support (default yes)], [enable_nfq="$enableval"])

if test x"$enable_nfq" = "xyes"; then
	AC_CHECK_HEADER([libnetfilter_queue/libnetfilter_queue.h],[enable_nfq="yes"],[enable_nfq=""])

	if test x"$enable_nfq" = "xyes"; then
		AC_CHECK_LIB([netfilter_queue],[nfq_open],[enable_nfq="yes"],[enable_nfq=""])
	fi
fi



dnl **************************************************
dnl * openssl Support                                *
dnl **************************************************
AC_DEFUN([CHECK_CRYPTO],
[
    AC_SUBST(LIBCRYPTO_CXXFLAGS)
    AC_SUBST(LIBCRYPTO_LDFLAGS)
    
    for dir in $withval /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr; do
        ssldir="$dir"
        if test -f "$dir/include/openssl/sha.h"; then
            found_ssl="yes";
            LIBCRYPTO_CXXFLAGS="$CXXFLAGS -I$ssldir/include/openssl -DHAVE_CRYPTO=1";
            break;
        fi
        if test -f "$dir/include/sha.h"; then
            found_ssl="yes";
            LIBCRYPTO_CXXFLAGS="-I$ssldir/include/ -DHAVE_CRYPTO=1";
            break
        fi
    done

    if test x_$found_ssl != x_yes; then
		AC_MSG_CHECKING(for libcrypto)
        AC_MSG_ERROR(no)
    else
        LIBCRYPTO_LDFLAGS="-lcrypto -L$ssldir/lib";

	    ORIG_LDFLAGS=${LDFLAGS}
	    LDFLAGS="$LDFLAGS $LIBCRYPTO_LDFLAGS"
	    AC_CHECK_LIB([crypto], [SHA1], [found_ssl="yes"], [found_ssl=""])
	    LDFLAGS=${ORIG_LDFLAGS}

	if test x_$found_ssl = x_yes; then
		AC_MSG_CHECKING(for libcrypto)
	        AC_MSG_RESULT(yes)
	else
		AC_MSG_CHECKING(for libcrypto)
		AC_MSG_ERROR(no)
	fi
    fi
])

CHECK_CRYPTO()


dnl **************************************************
dnl * libcurl Support                                *
dnl **************************************************
do_enable_curl="yes"

AC_ARG_ENABLE(curl, [  --enable-curl    enable http / ftp support via libcurl [[default yes]]], [do_enable_curl=$enableval])

AC_ARG_WITH(curl-include,
    [  --with-curl-include=PATH	specify path to curl include files],
    [curl_inc=$withval],
    [curl_inc=no])

AC_ARG_WITH(curl-lib,
    [  --with-curl-lib=PATH	specify path to curl client library],
    [curl_lib=$withval],
    [curl_lib=no])


if test x$do_enable_curl = "xyes"; then
    orig_cppflags=$CPPFLAGS
    orig_libs=$LIBS

    CURL_INCLUDE=""
    CURL_LIB=""
    
    if test "x$curl_inc" != xno; then
      CURL_INCLUDE+=" -I$curl_inc"
    fi

    if test "x$curl_lib" != "xno"; then
        CURL_LIB+=" -L$curl_lib"
    fi
    
    AC_PATH_PROG(LIBCURL_CONFIG, curl-config, no)
    if test "$LIBCURL_CONFIG" = "no" ; then
	AC_MSG_WARN([libcurl curl-config was not found in PATH])
    else
        CURL_INCLUDE+=" `curl-config --cflags`"
   	CURL_LIB+=" `curl-config --libs`"
    fi

    CPPFLAGS+=$CURL_INCLUDE
    LDFLAGS+=$CURL_LIB
    
    AC_CHECK_LIB([curl], [curl_multi_socket_action], [enable_curl="yes"], [enable_curl=""])

    if test x$enable_curl = "xyes"; then
        AC_DEFINE(HAVE_LIBCURL, 1,
              [Define if you want to use libcurl])
    fi

    CPPFLAGS=$orig_cppflags
    LIBS=$orig_libs
fi

AC_SUBST([CURL_INCLUDE])
AC_SUBST([CURL_LIB])


AC_DEFUN([ACX_PTHREAD], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_SAVE
AC_LANG_C
acx_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, acx_pthread_ok=yes)
        AC_MSG_RESULT($acx_pthread_ok)
        if test x"$acx_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all, and "pthread-config"
# which is a program returning the flags for the Pth emulation library.

acx_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread --thread-safe -mt pthread-config"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
#      ... -mt is also the pthreads flag for HP/aCC
# pthread: Linux, etcetera
# --thread-safe: KAI C++
# pthread-config: use pthread-config program (for GNU Pth library)

case "${host_cpu}-${host_os}" in
        *solaris*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthreads/-mt/
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        acx_pthread_flags="-pthreads pthread -mt -pthread $acx_pthread_flags"
        ;;
esac

if test x"$acx_pthread_ok" = xno; then
for flag in $acx_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

                pthread-config)
                AC_CHECK_PROG(acx_pthread_config, pthread-config, yes, no)
                if test x"$acx_pthread_config" = xno; then continue; fi
                PTHREAD_CFLAGS="`pthread-config --cflags`"
                PTHREAD_LIBS="`pthread-config --ldflags` `pthread-config --libs`"
                ;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK([#include <pthread.h>],
                    [pthread_t th; pthread_join(th, 0);
                     pthread_create(0,0,0,0); pthread_mutex_trylock(0); ],
                    [acx_pthread_ok=yes])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($acx_pthread_ok)
        if test "x$acx_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$acx_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: JOINABLE attribute is called UNDETACHED.
        AC_MSG_CHECKING([for joinable pthread attribute])
        attr_name=unknown
        for attr in PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_UNDETACHED; do
            AC_TRY_LINK([#include <pthread.h>], [int attr=$attr; return attr;],
                        [attr_name=$attr; break])
        done
        AC_MSG_RESULT($attr_name)
        if test "$attr_name" != PTHREAD_CREATE_JOINABLE; then
            AC_DEFINE_UNQUOTED(PTHREAD_CREATE_JOINABLE, $attr_name,
                               [Define to necessary symbol if this constant
                                uses a non-standard name on your system.])
        fi

        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
        case "${host_cpu}-${host_os}" in
            *-aix* | *-freebsd* | *-darwin*) flag="-D_THREAD_SAFE";;
            *solaris* | *-osf* | *-hpux*) flag="-D_REENTRANT";;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
            PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with xlc_r or cc_r
        if test x"$GCC" != xyes; then
          AC_CHECK_PROGS(PTHREAD_CC, xlc_r cc_r, ${CC})
        else
          PTHREAD_CC=$CC
        fi
else
        PTHREAD_CC="$CC"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$acx_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        acx_pthread_ok=no
        $2
fi
AC_LANG_RESTORE
])dnl ACX_PTHREAD


ACX_PTHREAD( [LIBS="$PTHREAD_LIBS $LIBS"
	      CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"],
	     [AC_MSG_ERROR([No pthreads support found, please install])] )



AM_CONDITIONAL(LIBEMU_MODULE, [test x$enable_libemu = "xyes"])
AM_CONDITIONAL(NFQ_MODULE, [test x$enable_nfq = "xyes"])
AM_CONDITIONAL(PYTHON_MODULE, [test x$enable_python = "xyes"])
AM_CONDITIONAL(CURL_MODULE, [test x$enable_curl = "xyes"])
AM_CONDITIONAL(PGSQL_MODULE, [test x$enable_pgsql = "xyes"])



AC_PROG_MAKE_SET

AC_OUTPUT([
	Makefile
	src/Makefile
	src/core/Makefile
	src/log-irc/Makefile
	src/dynserv-nfqueue/Makefile
	src/dynserv-mirror/Makefile
	src/filestore-streams/Makefile
	src/shellcode-libemu/Makefile
	src/embed-python/Makefile
	src/log-file/Makefile
	src/filestore-binaries/Makefile
	src/download-tftp/Makefile
	src/download-curl/Makefile
	src/submit-mwserv/Makefile
	src/postgresql/Makefile
	])


if test x"$enable_libemu" != "xyes"; then
	AC_MSG_WARN([libemu not enabled/found, this severely decreases functionality!])
fi

if test x"$enable_nfq" != "xyes"; then
	AC_MSG_WARN([libnetfilter_queue not enabled/found, mirror mode not possible!])
fi

if test x"$enable_python" != "xyes"; then
	AC_MSG_WARN([python3 not enabled/found, no service emulation possible!])
fi

if test x"$enable_curl" != "xyes"; then
	AC_MSG_WARN([libcurl not enabled/found, you cannot download http / ftp URLs!])
	AC_MSG_WARN([libcurl not enabled/found, submit-mwserv not available!])
fi

if test x"$enable_pgsql" != "xyes"; then
	AC_MSG_WARN([libpq not enabled/found, modules interacting with a PostgreSQL server will not work!])
fi
