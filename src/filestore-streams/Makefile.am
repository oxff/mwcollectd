# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = filestore-streams.la

filestore_streams_la_SOURCES = filestore-streams.cpp
filestore_streams_la_LDFLAGS = -module -no-undefined -avoid-version

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log/mwcollectd
