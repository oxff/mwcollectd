# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = log-file.la

log_file_la_SOURCES  = log-file.cpp
log_file_la_SOURCES += LogFile.cpp
log_file_la_LDFLAGS  = -module -no-undefined -avoid-version
