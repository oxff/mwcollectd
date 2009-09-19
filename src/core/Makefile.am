# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -DMWCOLLECTD_CORE -I../include/ -Wall -Werror -Wno-deprecated


sbin_PROGRAMS  = mwcollectd

mwcollectd_LDFLAGS = $(LIBCRYPTO_LDFLAGS)
mwcollectd_CXXFLAGS = $(LIBCRYPTO_CXXFLAGS)

mwcollectd_SOURCES  = mwcollectd.cpp
mwcollectd_SOURCES += Daemon.cpp
mwcollectd_SOURCES += HashManager.cpp
