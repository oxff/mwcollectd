# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -DMWCOLLECTD_CORE -DCFGPREFIX=\"@prefix@\" -I../include/ -Wall -Werror -Wno-deprecated


bin_PROGRAMS  = mwcollectd

mwcollectd_SOURCES  = mwcollectd.cpp
mwcollectd_SOURCES += Daemon.cpp
