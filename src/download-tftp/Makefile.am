# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = download-tftp.la

download_tftp_la_SOURCES  = download-tftp.cpp
download_tftp_la_SOURCES += TftpSocket.cpp
download_tftp_la_LDFLAGS  = -module -no-undefined -avoid-version
