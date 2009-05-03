# mwcollectd autoconf input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AC_PREREQ(2.59)
AC_INIT([mwcollectd], [4.0.0], [gw@mwcollect.org])
AM_INIT_AUTOMAKE([mwcollectd], [4.0.0])

AC_REVISION([1])

AC_PROG_CXX
AC_PROG_LIBTOOL
AC_LANG_CPLUSPLUS



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
dnl * openssl Support                                *
dnl **************************************************
AC_DEFUN([CHECK_CRYPTO],
[AC_MSG_CHECKING(for libcrypto)
    
    for dir in $withval /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr; do
        ssldir="$dir"
        if test -f "$dir/include/openssl/sha.h"; then
            found_ssl="yes";
            CFLAGS="$CFLAGS -I$ssldir/include/openssl -DHAVE_CRYPTO=1";
            CXXFLAGS="$CXXFLAGS -I$ssldir/include/openssl -DHAVE_CRYPTO=1";
            break;
        fi
        if test -f "$dir/include/sha.h"; then
            found_ssl="yes";
            CFLAGS="$CFLAGS -I$ssldir/include/ -DHAVE_CRYPTO=1";
            CXXFLAGS="$CXXFLAGS -I$ssldir/include/ -DHAVE_CRYPTO=1";
            break
        fi
    done
    if test x_$found_ssl != x_yes; then
        AC_MSG_ERROR(no)
    else
        LIBS="$LIBS -lcrypto";
        LDFLAGS="$LDFLAGS -L$ssldir/lib";
        HAVE_CRYPTO=yes
        AC_MSG_RESULT(yes)
    fi
    AC_SUBST(HAVE_CRYPTO)
])dnl

CHECK_CRYPTO()



AC_PROG_MAKE_SET

AC_OUTPUT([
	Makefile
	src/Makefile
	src/core/Makefile
	src/log-irc/Makefile
	src/dynserv-nfqueue/Makefile
	])
