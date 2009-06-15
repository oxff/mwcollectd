# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = shellcode-libemu.la

shellcode_libemu_la_SOURCES  = shellcode-libemu.cpp
shellcode_libemu_la_SOURCES += AnalyzerThread.cpp
shellcode_libemu_la_CPPFLAGS = $(LIBEMU_CPPFLAGS)
shellcode_libemu_la_LDFLAGS = -module -no-undefined -avoid-version $(LIBEMU_LDFLAGS)
