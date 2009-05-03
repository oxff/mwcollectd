# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = dynserv-mirror.la

dynserv_mirror_la_SOURCES  = dynserv-mirror.cpp
dynserv_mirror_la_SOURCES += MirrorServer.cpp
dynserv_mirror_la_SOURCES += MirrorEndpoint.cpp

dynserv_mirror_la_LDFLAGS = -module -avoid-version
