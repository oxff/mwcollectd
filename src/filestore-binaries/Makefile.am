# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = filestore-binaries.la

filestore_binaries_la_SOURCES = filestore-binaries.cpp
filestore_binaries_la_LDFLAGS = -module -no-undefined -avoid-version

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log/mwcollectd
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log/mwcollectd/binaries
