# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/ $(CURL_INCLUDE)
AM_LDFLAGS =

pkglib_LTLIBRARIES = download-curl.la

download_curl_la_SOURCES  = download-curl.cpp
download_curl_la_SOURCES += CurlSocket.cpp
download_curl_la_LDFLAGS  = -module -no-undefined -avoid-version $(CURL_LIB)
