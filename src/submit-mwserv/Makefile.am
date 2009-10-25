# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = submit-mwserv.la

submit_mwserv_la_SOURCES  = submit-mwserv.cpp

submit_mwserv_la_LDFLAGS  = -module -no-undefined -avoid-version
